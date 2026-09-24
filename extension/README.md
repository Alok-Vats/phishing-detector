# Phishing Detection Browser Extension

This Chromium-compatible browser extension automatically analyzes the active tab's URL against your local Phishing Detection API.

## Setup Instructions

1. **Open Chrome / Edge / Brave**.
2. Navigate to `chrome://extensions/` (or equivalent in your browser).
3. Enable **Developer mode** (usually a toggle in the top-right corner).
4. Click **Load unpacked**.
5. Select this `extension` folder located at `mProject (Copy)/extension`.
6. Pin the extension to your toolbar.

## Configuration

By default, the extension points to `http://127.0.0.1:5000/api/v1/analyze/url`.
Ensure your Flask backend is running.

If your API requires authentication:
1. Click the extension icon.
2. If it fails with "Unauthorized", click **Set API URL**.
3. Enter a valid JWT/Bearer token generated from your backend.
4. Click **Save & Retry**.

## Security Constraints
- **No Local ML**: To ensure the extension stays lightweight and doesn't expose proprietary weights, all analysis runs on the backend.
- **No DOM Access**: The extension does not read the active tab's DOM structure; it only requests the URL. Full static HTML analysis is handled safely server-side to prevent client-side exploits.
- **No Blocking**: This extension currently operates in "Audit Mode" only, meaning it will not automatically kill/block network requests.
