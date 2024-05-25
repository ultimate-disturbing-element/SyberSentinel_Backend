const express = require("express");
const net = require('net');
const psl = require('psl');
const axios = require('axios');
const dns = require("dns");
const tls = require("tls");
const util = require('util');
const cheerio = require('cheerio');
const puppeteer = require('puppeteer');
const https = require('https');

const router = express.Router();

// Get Ip Address
router.get("/get-ip/", (req, res) => {
  const { url } = req.query;
  try {
    const address = url.replace("https://", "").replace("http://", "");
    // Perform DNS lookup for the modified address
    dns.lookup(address, (err, ip, family) => {
      if (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to perform DNS lookup." });
      }
      // Send the response with IP address and family
      res.json({ url, ip, family });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error." });
  }
});

// SSL Certification
router.get("/ssl", (req, res) => {
  const { url } = req.query;

  try {
    const parsedUrl = new URL(url);
    const options = {
      host: parsedUrl.hostname,
      port: parsedUrl.port || 443,
      servername: parsedUrl.hostname,
      rejectUnauthorized: false,
    };

    const socket = tls.connect(options, () => {
      if (!socket.authorized) {
        res
          .status(500)
          .json({
            error: `SSL handshake not authorized. Reason: ${socket.authorizationError}`,
          });
      }

      const cert = socket.getPeerCertificate();
      if (!cert || Object.keys(cert).length === 0) {
        res
          .status(500)
          .json({ error: "No certificate presented by the server." });
      }

      const { raw, issuerCertificate, ...certWithoutRaw } = cert;
      res.json(certWithoutRaw);
      socket.end();
    });

    socket.on("error", (error) => {
      res
        .status(500)
        .json({ error: `Error fetching site certificate: ${error.message}` });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// http Security
router.get('/http-security',async (req,res)=>{
    const {url} = req.query;
    const fullUrl = url.startsWith('http') ? url : `http://${url}`;
  
  try {
    const response = await axios.get(fullUrl);
    const headers = response.headers;
    res.json({
      strictTransportPolicy: headers['strict-transport-security'] ? true : false,
      xFrameOptions: headers['x-frame-options'] ? true : false,
      xContentTypeOptions: headers['x-content-type-options'] ? true : false,
      xXSSProtection: headers['x-xss-protection'] ? true : false,
      contentSecurityPolicy: headers['content-security-policy'] ? true : false,
    });
  } catch (error) {
    res.json({
      statusCode: 500,
      body: JSON.stringify({ error: error.message }),
    });
  }
})

// Socials Tags
router.get('/social-tags',async (req,res)=>{
    const {url} = req.query;
// Check if url includes protocol
if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }
  
  try {
    const response = await axios.get(url);
    const html = response.data;
    const $ = cheerio.load(html);
    
    const metadata = {
      // Basic meta tags
      title: $('head title').text(),
      description: $('meta[name="description"]').attr('content'),
      keywords: $('meta[name="keywords"]').attr('content'),
      canonicalUrl: $('link[rel="canonical"]').attr('href'),

      // OpenGraph Protocol
      ogTitle: $('meta[property="og:title"]').attr('content'),
      ogType: $('meta[property="og:type"]').attr('content'),
      ogImage: $('meta[property="og:image"]').attr('content'),
      ogUrl: $('meta[property="og:url"]').attr('content'),
      ogDescription: $('meta[property="og:description"]').attr('content'),
      ogSiteName: $('meta[property="og:site_name"]').attr('content'),
      
      // Twitter Cards
      twitterCard: $('meta[name="twitter:card"]').attr('content'),
      twitterSite: $('meta[name="twitter:site"]').attr('content'),
      twitterCreator: $('meta[name="twitter:creator"]').attr('content'),
      twitterTitle: $('meta[name="twitter:title"]').attr('content'),
      twitterDescription: $('meta[name="twitter:description"]').attr('content'),
      twitterImage: $('meta[name="twitter:image"]').attr('content'),

      // Misc
      themeColor: $('meta[name="theme-color"]').attr('content'),
      robots: $('meta[name="robots"]').attr('content'),
      googlebot: $('meta[name="googlebot"]').attr('content'),
      generator: $('meta[name="generator"]').attr('content'),
      viewport: $('meta[name="viewport"]').attr('content'),
      author: $('meta[name="author"]').attr('content'),
      publisher: $('link[rel="publisher"]').attr('href'),
      favicon: $('link[rel="icon"]').attr('href')
    };

    if (Object.keys(metadata).length === 0) {
      res.json({ skipped: 'No metadata found' });
    }
    res.json(metadata);
  } catch (error) {
    res.json({
      statusCode: 500,
      error: 'Failed fetching data',
    });
  }
})

// dns
router.get('/dns',async (req,res)=>{
    const {url} = req.query;
    let hostname = url;
  // Handle URLs by extracting hostname
  if (hostname.startsWith('http://') || hostname.startsWith('https://')) {
    hostname = new URL(hostname).hostname;
  }

  try {
    const lookupPromise = util.promisify(dns.lookup);
    const resolve4Promise = util.promisify(dns.resolve4);
    const resolve6Promise = util.promisify(dns.resolve6);
    const resolveMxPromise = util.promisify(dns.resolveMx);
    const resolveTxtPromise = util.promisify(dns.resolveTxt);
    const resolveNsPromise = util.promisify(dns.resolveNs);
    const resolveCnamePromise = util.promisify(dns.resolveCname);
    const resolveSoaPromise = util.promisify(dns.resolveSoa);
    const resolveSrvPromise = util.promisify(dns.resolveSrv);
    const resolvePtrPromise = util.promisify(dns.resolvePtr);

    const [a, aaaa, mx, txt, ns, cname, soa, srv, ptr] = await Promise.all([
      lookupPromise(hostname),
      resolve4Promise(hostname).catch(() => []), // A record
      resolve6Promise(hostname).catch(() => []), // AAAA record
      resolveMxPromise(hostname).catch(() => []), // MX record
      resolveTxtPromise(hostname).catch(() => []), // TXT record
      resolveNsPromise(hostname).catch(() => []), // NS record
      resolveCnamePromise(hostname).catch(() => []), // CNAME record
      resolveSoaPromise(hostname).catch(() => []), // SOA record
      resolveSrvPromise(hostname).catch(() => []), // SRV record
      resolvePtrPromise(hostname).catch(() => [])  // PTR record
    ]);

    res.json({
      A: a,
      AAAA: aaaa,
      MX: mx,
      TXT: txt,
      NS: ns,
      CNAME: cname,
      SOA: soa,
      SRV: srv,
      PTR: ptr
    });
  } catch (error) {
    throw new Error(error.message);
  }
})

// header
router.get('/header',async (req,res)=>{
    const {url} = req.query;
    try {
        const response = await axios.get(url, {
          validateStatus: function (status) {
            return status >= 200 && status < 600; // Resolve only if the status code is less than 600
          },
        });
    
        res.json(response.headers);
      } catch (error) {
        throw new Error(error.message);
      }
})

// Cookies
router.get('/cookies', async (req, res) => {
  const {url} = req.query;
  if (!url) {
    return res.status(400).send({ error: 'URL parameter is required' });
  }

  const getPuppeteerCookies = async (url) => {
    const browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    try {
      const page = await browser.newPage();
      const navigationPromise = page.goto(url, { waitUntil: 'networkidle2' });
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Puppeteer took too long!')), 3000)
      );
      await Promise.race([navigationPromise, timeoutPromise]);
      return await page.cookies();
    } finally {
      await browser.close();
    }
  };

  let headerCookies = null;
  let clientCookies = null;

  try {
    const response = await axios.get(url, {
      withCredentials: true,
      maxRedirects: 5,
    });
    headerCookies = response.headers['set-cookie'];
  } catch (error) {
    if (error.response) {
      return res.status(500).send({ error: `Request failed with status ${error.response.status}: ${error.message}` });
    } else if (error.request) {
      return res.status(500).send({ error: `No response received: ${error.message}` });
    } else {
      return res.status(500).send({ error: `Error setting up request: ${error.message}` });
    }
  }

  try {
    clientCookies = await getPuppeteerCookies(url);
  } catch (_) {
    clientCookies = null;
  }

  if (!headerCookies && (!clientCookies || clientCookies.length === 0)) {
    return res.status(200).send({ skipped: 'No cookies' });
  }

  res.status(200).send({ headerCookies, clientCookies });
});

// hsts
router.get('/hsts', async (req, res) => {
  const { url } = req.query;

  const errorResponse = (message, statusCode = 500) => {
    return res.status(statusCode).json({ error: message });
  };

  const hstsIncompatible = (message, compatible = false, hstsHeader = null) => {
    return res.json({ message, compatible, hstsHeader });
  };

  try {
    const req = https.request(url, response => {
      const headers = response.headers;
      const hstsHeader = headers['strict-transport-security'];

      if (!hstsHeader) {
        return hstsIncompatible(`Site does not serve any HSTS headers.`);
      } else {
        const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/);
        const includesSubDomains = hstsHeader.includes('includeSubDomains');
        const preload = hstsHeader.includes('preload');

        if (!maxAgeMatch || parseInt(maxAgeMatch[1]) < 10886400) {
          return hstsIncompatible(`HSTS max-age is less than 10886400.`);
        } else if (!includesSubDomains) {
          return hstsIncompatible(`HSTS header does not include all subdomains.`);
        } else if (!preload) {
          return hstsIncompatible(`HSTS header does not contain the preload directive.`);
        } else {
          return hstsIncompatible(`Site is compatible with the HSTS preload list!`, true, hstsHeader);
        }
      }
    });

    req.on('error', error => {
      return errorResponse(`Error making request: ${error.message}`);
    });

    req.end();
  } catch (error) {
    return errorResponse(`Error: ${error.message}`);
  }
});

// threats
router.get('/threats',async (req,res)=>{})

module.exports = router;
