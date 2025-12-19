require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

const upload = multer();

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
})

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
});

function checkAuth(req, res, next) {
  const JWT_SECRET = process.env.JWT_SECRET;
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  const ADMIN_USERNAME  = process.env.ADMIN_USERNAME;
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

  if (username !== ADMIN_USERNAME) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  bcrypt.compare(password, ADMIN_PASSWORD, (err, result) => {
    if (!result) return res.status(401).json({ error: 'Invalid credentials' });

    const JWT_EXPIRY = process.env.JWT_EXPIRY;
    const JWT_SECRET = process.env.JWT_SECRET;

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
    res.json({ token });
  });
});

const tokenBlacklist = new Set();

app.post('/api/logout', checkAuth, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token provided' });

  if(isTokenBlacklisted(token)) {
    return res.status(403).json({ message: 'Token is already blacklisted' });
  }

  tokenBlacklist.add(token);
  res.json({ message: 'Logged out successfully' });
});

function isTokenBlacklisted(token) {
  return tokenBlacklist.has(token);
}

app.post('/api/post', upload.any(), async (req, res) => {
  try {
    const site = req.cookies.selectedSite;
    const authHeader = req.headers.authorization;
    const filesBase64 = {};

    // Convert uploaded files to base64
    req.files.forEach(file => {
      filesBase64[file.fieldname] = {
        filename: file.originalname,
        mimetype: file.mimetype,
        data: file.buffer.toString('base64')
      };
    });

    let sections = [];
    try {
      sections = JSON.parse(req.body.sections || '[]');
    } catch {
      sections = [];
    }

    const payload = {
      title: req.body.title,
      summary: req.body.summary,
      category: req.body.category,
      sections,
      images: filesBase64
    };

    const siteBaseUrl = getSiteBaseURL(req);

    const response = await fetch(`${siteBaseUrl}/api/admin-panel/post`, {
      method: 'POST',
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const result = await response.json();
    res.json(result);
  } catch (err) {
    console.error('Forwarding error:', err);
    res.status(500).json({ error: 'Forwarding failed' });
  }
});

app.get('/api/post/:id', checkAuth, async(req, res) => {
  try {
    const postId = req.params.id;
    const authHeader = req.headers.authorization;

    const siteBaseUrl = getSiteBaseURL(req);

    const response = await fetch(`${siteBaseUrl}/api/post/${postId}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': authHeader,
      }
    });

    if (!response.ok) {
      return res.status(response.status).json({ error: `Failed to fetch post` });
    }

    const data = await response.json();
    res.json(data);

  } catch (err) {
    console.error('Fetch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/post', async (req, res) => {
  try {
    const siteBaseUrl = getSiteBaseURL(req);

    const response = await fetch(`${siteBaseUrl}/posts`);
    let data = await response.json();

    data.map(post => {
      post.image = `https://${req.cookies.selectedSite}.com/${post.image}`;
    });

    res.json(data);
  } catch (err) {
      console.log(err);
      res.status(500).json({ message: 'Failed to fetch posts' });
  }
});

app.put('/api/post/:id', checkAuth, async(req, res) => {
  try {
    const postId = req.params.id;
    const authHeader = req.headers.authorization;

    const siteBaseUrl = getSiteBaseURL(req);

    const response = await fetch(`${siteBaseUrl}/api/blogs/${postId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': authHeader,
      },
      body: JSON.stringify(req.body), 
    });

    if (response.ok) {
      res.json({ message: 'Blog updated successfully'});
    }
  } catch (err) {
      console.log(err);
      res.status(500).json({ message: 'Failed to fetch posts' });
  }
});

app.delete('/api/post/:id', checkAuth, async(req, res) => {

  try {
    const postId = req.params.id;
    const authHeader = req.headers.authorization;

    const siteBaseUrl = getSiteBaseURL(req);

    const response = await fetch(`${siteBaseUrl}/api/blogs/${postId}`, {
      method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authHeader,
        }
      }
    );

    if (response.ok) {
      res.json({status: 'success' });
    } else  {
      res.status(500).json({ message: 'Failed to delete post'});
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'Failed to delete post'});
  }
  
});

app.get("/api/highlighted-sections", async (req, res) => {
  try {
    const siteBaseUrl = getSiteBaseURL(req);

    const response = await fetch(`${siteBaseUrl}/api/highlighted-sections`);
    const highlightedPosts = await response.json();

    const highlightedPostsQuantity = getHighlightedPostsQuantity(req.cookies.selectedSite);

    const highlightedData = {
      highlightedPosts,
      highlightedPostsQuantity
    }

    return res.json(highlightedData);
  } catch(err) {
    console.log(err);
    res.status(500).json({ error: 'Failed to fetch highlighted sections.' });
  }
});

function getHighlightedPostsQuantity(site) {
  const templateA = ['aboutfashions', 'genexfinance', 'thefactfinding', 'foodbitez', 'kafeyworld'];
  const templateB = ['homeztravel', 'nurturelifes', 'thetechgadgetz'];

  const configA = {
    topStories: 4,
    mostPopular: 4,
    inFocus: 5,
  };

  const configB = {
    topPosts: 4,
    trendingPosts: 3,
    latestPosts: 5,
    whatsNewPosts: 3,
    gridPosts: 5,
    bottomPosts: 8,
  };

  if (templateA.includes(site)) {
    return configA;
  }

  if (templateB.includes(site)) {
    return configB;
  }

  return null;
}

app.post("/api/highlighted-sections", checkAuth, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const siteBaseUrl = getSiteBaseURL(req);

    const response = await fetch(`${siteBaseUrl}/api/highlighted-sections`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': authHeader,
      },
      body: JSON.stringify(req.body),
    });

    if (response.ok) {
      res.json({ status: 'success' });
    } else  {
      res.status(500).json({ error: 'Failed to update highlighted sections' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update highlighted sections' });
  }
});

function getSiteBaseURL(req) {
    const useLocal = process.env.USE_SITE_LOCALHOST === "true";

    if (useLocal) {
        const siteLocalhost = {
          aboutfashions: 'http://localhost:4000',
          foodbitez: 'http://localhost:8000',
          genexfinance: 'http://localhost:5000',
          thefactfinding: 'http://localhost:6000',
          nurturelifes: 'http://localhost:9000',
          kafeyworld: 'http://localhost:7000',
          homeztravel: 'http://localhost:10000',
          thetechgadgetz: 'http://localhost:3001',
        }
        return siteLocalhost[req.cookies.selectedSite];
    }

    const site = req.cookies.selectedSite;
    return `https://${site}.com`;
};

app.get('/api/verify-token', checkAuth, (req, res) => {
  res.sendStatus(200);
});

app.listen(PORT, () => {
    console.log(`Server running on ${PORT}`);
});


