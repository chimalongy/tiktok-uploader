/**
 * TikTok Video Upload Platform - Express Server
 *
 * Uses TikTok Content Posting API v2
 * Docs: https://developers.tiktok.com/doc/content-posting-api-get-started
 *
 * SETUP:
 * 1. Register app at https://developers.tiktok.com/
 * 2. Add "Content Posting API" product to your app
 * 3. Enable video.upload and video.publish scopes
 * 4. Set redirect URI to: http://localhost:3000/auth/callback
 * 5. For sandbox: toggle to Sandbox mode, add target users
 *
 * Install deps: npm install express axios multer dotenv cookie-parser
 */

import 'dotenv/config';
import express from 'express';
import axios from 'axios';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Multer config — store uploads in /tmp
const upload = multer({
  dest: '/tmp/tiktok-uploads/',
  limits: { fileSize: 4 * 1024 * 1024 * 1024 }, // 4GB max
});

// ─── CONFIG ─────────────────────────────────────────────────────────────────
const {
  TIKTOK_CLIENT_KEY,
  TIKTOK_CLIENT_SECRET,
  REDIRECT_URI = 'http://localhost:3000/auth/callback',
  PORT = 3000,
} = process.env;

const TIKTOK_AUTH_URL = 'https://www.tiktok.com/v2/auth/authorize/';
const TIKTOK_TOKEN_URL = 'https://open.tiktokapis.com/v2/oauth/token/';
const TIKTOK_API_BASE = 'https://open.tiktokapis.com/v2';
const TIKTOK_UPLOAD_BASE = 'https://open-upload.tiktokapis.com';

// In-memory token store (use a real DB / Redis in production)
const tokenStore = {};

// ─── STEP 1: OAUTH — Generate Auth URL ──────────────────────────────────────
// GET /auth/login
// Redirects user to TikTok's OAuth consent page.
// Requests scopes: video.upload (draft to inbox) + video.publish (direct post)
app.get('/auth/login', (req, res) => {
  const csrfState = crypto.randomBytes(16).toString('hex');

  // Store CSRF state in a simple session cookie
  res.cookie('tiktok_csrf', csrfState, { httpOnly: true, maxAge: 600000 });

  const params = new URLSearchParams({
    client_key: TIKTOK_CLIENT_KEY,
    scope: 'video.upload,video.publish,user.info.basic',
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    state: csrfState,
  });

  const authUrl = `${TIKTOK_AUTH_URL}?${params.toString()}`;
  console.log('[Auth] Redirecting to TikTok OAuth:', authUrl);
  res.redirect(authUrl);
});

// ─── STEP 2: OAUTH CALLBACK ──────────────────────────────────────────────────
// GET /auth/callback
// TikTok redirects here with ?code=...&state=...
// Exchange the code for an access_token + refresh_token
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).json({ error: `TikTok OAuth error: ${error}` });
  }

  // CSRF check
  const storedCsrf = req.cookies?.tiktok_csrf;
  if (!storedCsrf || storedCsrf !== state) {
    return res.status(403).json({ error: 'CSRF state mismatch' });
  }

  try {
    // Exchange authorization code for tokens
    const tokenRes = await axios.post(
      TIKTOK_TOKEN_URL,
      new URLSearchParams({
        client_key: TIKTOK_CLIENT_KEY,
        client_secret: TIKTOK_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: REDIRECT_URI,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, refresh_token, open_id, expires_in } = tokenRes.data;

    // Persist tokens (keyed by open_id)
    tokenStore[open_id] = {
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000,
    };

    console.log(`[Auth] Token stored for user: ${open_id}`);
    res.redirect(`/?open_id=${open_id}&status=authenticated`);
  } catch (err) {
    console.error('[Auth] Token exchange failed:', err.response?.data || err.message);
    res.status(500).json({ error: 'Token exchange failed', detail: err.response?.data });
  }
});

// ─── TOKEN REFRESH HELPER ────────────────────────────────────────────────────
async function getValidToken(open_id) {
  const stored = tokenStore[open_id];
  if (!stored) throw new Error('User not authenticated');

  // Refresh if expiring within 5 minutes
  if (Date.now() > stored.expires_at - 300000) {
    console.log(`[Auth] Refreshing token for: ${open_id}`);
    const refreshRes = await axios.post(
      TIKTOK_TOKEN_URL,
      new URLSearchParams({
        client_key: TIKTOK_CLIENT_KEY,
        client_secret: TIKTOK_CLIENT_SECRET,
        grant_type: 'refresh_token',
        refresh_token: stored.refresh_token,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = refreshRes.data;
    tokenStore[open_id] = {
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000,
    };
  }

  return tokenStore[open_id].access_token;
}

// ─── STEP 3: QUERY CREATOR INFO ─────────────────────────────────────────────
// GET /api/creator-info?open_id=xxx
// Required before direct post — returns privacy options, max duration, etc.
app.get('/api/creator-info', async (req, res) => {
  const { open_id } = req.query;
  try {
    const token = await getValidToken(open_id);

    const response = await axios.post(
      `${TIKTOK_API_BASE}/post/publish/creator_info/query/`,
      {},
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
    );

    res.json(response.data);
  } catch (err) {
    console.error('[Creator Info] Error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// ─── STEP 4A: UPLOAD VIDEO TO INBOX (DRAFT MODE) ────────────────────────────
// POST /api/upload/draft
// Uploads video as a TikTok Inbox draft — user completes posting in TikTok app
// Requires: video.upload scope
app.post('/api/upload/draft', upload.single('video'), async (req, res) => {
  const { open_id } = req.body;
  const file = req.file;

  if (!file) return res.status(400).json({ error: 'No video file provided' });

  try {
    const token = await getValidToken(open_id);
    const fileSize = file.size;
    const chunkSize = Math.min(fileSize, 64 * 1024 * 1024); // max 64MB per chunk
    const totalChunks = Math.ceil(fileSize / chunkSize);

    console.log(`[Draft Upload] File: ${file.originalname}, Size: ${fileSize}, Chunks: ${totalChunks}`);

    // 1. Initialize upload
    const initRes = await axios.post(
      `${TIKTOK_API_BASE}/post/publish/inbox/video/init/`,
      {
        source_info: {
          source: 'FILE_UPLOAD',
          video_size: fileSize,
          chunk_size: chunkSize,
          total_chunk_count: totalChunks,
        },
      },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json; charset=UTF-8' } }
    );

    const { publish_id, upload_url } = initRes.data.data;
    console.log(`[Draft Upload] publish_id: ${publish_id}`);

    // 2. Upload chunks
    const fileBuffer = fs.readFileSync(file.path);
    for (let i = 0; i < totalChunks; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, fileSize);
      const chunk = fileBuffer.slice(start, end);

      await axios.put(upload_url, chunk, {
        headers: {
          'Content-Type': 'video/mp4',
          'Content-Range': `bytes ${start}-${end - 1}/${fileSize}`,
          'Content-Length': chunk.length,
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      });
      console.log(`[Draft Upload] Chunk ${i + 1}/${totalChunks} uploaded`);
    }

    // 3. Clean up temp file
    fs.unlinkSync(file.path);

    res.json({
      success: true,
      publish_id,
      message: 'Video uploaded to TikTok inbox. User must open TikTok to complete posting.',
    });
  } catch (err) {
    if (req.file?.path) fs.unlinkSync(req.file.path);
    console.error('[Draft Upload] Error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// ─── STEP 4B: DIRECT POST VIDEO ─────────────────────────────────────────────
// POST /api/upload/direct
// Posts video directly to TikTok profile (no inbox step)
// Requires: video.publish scope + app audit for public content
// NOTE: Unaudited apps → posts are SELF_ONLY (private)
app.post('/api/upload/direct', upload.single('video'), async (req, res) => {
  const {
    open_id,
    title = '',
    privacy_level = 'SELF_ONLY', // SELF_ONLY | MUTUAL_FOLLOW_FRIENDS | PUBLIC_TO_EVERYONE
    disable_comment = false,
    disable_duet = false,
    disable_stitch = false,
    video_cover_timestamp_ms = 1000,
  } = req.body;

  const file = req.file;
  if (!file) return res.status(400).json({ error: 'No video file provided' });

  try {
    const token = await getValidToken(open_id);
    const fileSize = file.size;
    const chunkSize = Math.min(fileSize, 64 * 1024 * 1024);
    const totalChunks = Math.ceil(fileSize / chunkSize);

    console.log(`[Direct Post] Initiating for user: ${open_id}`);

    // 1. Initialize direct post
    const initRes = await axios.post(
      `${TIKTOK_API_BASE}/post/publish/video/init/`,
      {
        post_info: {
          title,
          privacy_level,
          disable_comment: Boolean(disable_comment),
          duet_disabled: Boolean(disable_duet),
          stitch_disabled: Boolean(disable_stitch),
          video_cover_timestamp_ms: Number(video_cover_timestamp_ms),
        },
        source_info: {
          source: 'FILE_UPLOAD',
          video_size: fileSize,
          chunk_size: chunkSize,
          total_chunk_count: totalChunks,
        },
      },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json; charset=UTF-8' } }
    );

    const { publish_id, upload_url } = initRes.data.data;
    console.log(`[Direct Post] publish_id: ${publish_id}`);

    // 2. Upload file in chunks
    const fileBuffer = fs.readFileSync(file.path);
    for (let i = 0; i < totalChunks; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, fileSize);
      const chunk = fileBuffer.slice(start, end);

      await axios.put(upload_url, chunk, {
        headers: {
          'Content-Type': 'video/mp4',
          'Content-Range': `bytes ${start}-${end - 1}/${fileSize}`,
          'Content-Length': chunk.length,
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      });
    }

    fs.unlinkSync(file.path);
    res.json({ success: true, publish_id });
  } catch (err) {
    if (req.file?.path) fs.unlinkSync(req.file.path);
    console.error('[Direct Post] Error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// ─── STEP 4C: DIRECT POST FROM URL ──────────────────────────────────────────
// POST /api/upload/from-url
// Post a video hosted on a verified domain URL directly to TikTok
// No file upload needed — TikTok pulls from the URL
app.post('/api/upload/from-url', async (req, res) => {
  const {
    open_id,
    video_url,
    title = '',
    privacy_level = 'SELF_ONLY',
  } = req.body;

  if (!video_url) return res.status(400).json({ error: 'video_url is required' });

  try {
    const token = await getValidToken(open_id);

    const initRes = await axios.post(
      `${TIKTOK_API_BASE}/post/publish/video/init/`,
      {
        post_info: { title, privacy_level },
        source_info: { source: 'PULL_FROM_URL', video_url },
      },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json; charset=UTF-8' } }
    );

    const { publish_id } = initRes.data.data;
    res.json({ success: true, publish_id, message: 'TikTok is fetching your video from the URL.' });
  } catch (err) {
    console.error('[URL Post] Error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// ─── STEP 5: POLL POST STATUS ────────────────────────────────────────────────
// GET /api/status/:publish_id?open_id=xxx
// Poll until status is PUBLISH_COMPLETE, FAILED, or still PROCESSING
app.get('/api/status/:publish_id', async (req, res) => {
  const { publish_id } = req.params;
  const { open_id } = req.query;

  try {
    const token = await getValidToken(open_id);

    const statusRes = await axios.post(
      `${TIKTOK_API_BASE}/post/publish/status/fetch/`,
      { publish_id },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json; charset=UTF-8' } }
    );

    res.json(statusRes.data);
  } catch (err) {
    console.error('[Status] Error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// ─── START ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🎵 TikTok Uploader running at http://localhost:${PORT}`);
  console.log(`   OAuth login: http://localhost:${PORT}/auth/login\n`);
  console.log('Make sure TIKTOK_CLIENT_KEY and TIKTOK_CLIENT_SECRET are set in .env');
});