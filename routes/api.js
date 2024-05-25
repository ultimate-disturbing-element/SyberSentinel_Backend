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
const urlLib = require('url');
const traceroute = require('traceroute');

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

// linked pages
router.get('/linked-pages', async (req, res) => {
  const { url } = req.query;

  try {
    const response = await axios.get(url);
    const $ = cheerio.load(response.data);
    const links = $('a[href]').map((i, link) => urlLib.resolve(url, $(link).attr('href'))).get();

    const internalLinks = [];
    const externalLinks = [];

    links.forEach(link => {
      if (link.startsWith(url)) {
        internalLinks.push(link);
      } else if (link.startsWith('http://') || link.startsWith('https://')) {
        externalLinks.push(link);
      }
    });

    // Return the result
    return res.json({ internal: internalLinks, external: externalLinks });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// redirects

router.get('/redirects', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  let redirects = [url];
  const got = await import('got');

  try {
    await got.default(url, {
      followRedirect: true,
      maxRedirects: 12,
      hooks: {
        beforeRedirect: [
          (options, response) => {
            const redirectUrl = response.headers.location;
            // Check for circular redirects
            if (redirects.includes(redirectUrl)) {
              throw new Error('Circular redirect detected');
            }
            redirects.push(redirectUrl);
          },
        ],
      },
    });

    res.json({ redirects });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// block-list
router.get('/block-list', async (req, res) => {
  const DNS_SERVERS = [
    { name: 'AdGuard', ip: '176.103.130.130' },
    { name: 'AdGuard Family', ip: '176.103.130.132' },
    { name: 'CleanBrowsing Adult', ip: '185.228.168.10' },
    { name: 'CleanBrowsing Family', ip: '185.228.168.168' },
    { name: 'CleanBrowsing Security', ip: '185.228.168.9' },
    { name: 'CloudFlare', ip: '1.1.1.1' },
    { name: 'CloudFlare Family', ip: '1.1.1.3' },
    { name: 'Comodo Secure', ip: '8.26.56.26' },
    { name: 'Google DNS', ip: '8.8.8.8' },
    { name: 'Neustar Family', ip: '156.154.70.3' },
    { name: 'Neustar Protection', ip: '156.154.70.2' },
    { name: 'Norton Family', ip: '199.85.126.20' },
    { name: 'OpenDNS', ip: '208.67.222.222' },
    { name: 'OpenDNS Family', ip: '208.67.222.123' },
    { name: 'Quad9', ip: '9.9.9.9' },
    { name: 'Yandex Family', ip: '77.88.8.7' },
    { name: 'Yandex Safe', ip: '77.88.8.88' },
  ];
  
  const knownBlockIPs = [
    '146.112.61.106', // OpenDNS
    '185.228.168.10', // CleanBrowsing
    '8.26.56.26',     // Comodo
    '9.9.9.9',        // Quad9
    '208.69.38.170',  // Some OpenDNS IPs
    '208.69.39.170',  // Some OpenDNS IPs
    '208.67.222.222', // OpenDNS
    '208.67.222.123', // OpenDNS FamilyShield
    '199.85.126.10',  // Norton
    '199.85.126.20',  // Norton Family
    '156.154.70.22',  // Neustar
    '77.88.8.7',      // Yandex
    '77.88.8.8',      // Yandex
    '::1',            // Localhost IPv6
    '2a02:6b8::feed:0ff', // Yandex DNS
    '2a02:6b8::feed:bad', // Yandex Safe
    '2a02:6b8::feed:a11', // Yandex Family
    '2620:119:35::35',    // OpenDNS
    '2620:119:53::53',    // OpenDNS FamilyShield
    '2606:4700:4700::1111', // Cloudflare
    '2606:4700:4700::1001', // Cloudflare
    '2001:4860:4860::8888', // Google DNS
    '2a0d:2a00:1::',        // AdGuard
    '2a0d:2a00:2::'         // AdGuard Family
  ];
  
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  const domain = new URL(url).hostname;
  const checkDomainAgainstDnsServers = async (domain) => {
    const results = [];
    for (let server of DNS_SERVERS) {
      const isDomainBlocked = async (domain, serverIP) => {
        return new Promise((resolve) => {
          dns.resolve4(domain, { server: serverIP }, (err, addresses) => {
            if (!err) {
              if (addresses.some(addr => knownBlockIPs.includes(addr))) {
                resolve(true);
                return;
              }
              resolve(false);
              return;
            }
      
            dns.resolve6(domain, { server: serverIP }, (err6, addresses6) => {
              if (!err6) {
                if (addresses6.some(addr => knownBlockIPs.includes(addr))) {
                  resolve(true);
                  return;
                }
                resolve(false);
                return;
              }
              if (err6.code === 'ENOTFOUND' || err6.code === 'SERVFAIL') {
                resolve(true);
              } else {
                resolve(false);
              }
            });
          });
        });
      };
      results.push({
        server: server.name,
        serverIp: server.ip,
        isBlocked: await isDomainBlocked(domain, server.ip),
      });
    }
    return results;
  };

  try {
    const results = await checkDomainAgainstDnsServers(domain);
    res.json({ blocklists: results });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// tls
router.get('/tls', async (req, res) => {
  const TLS_OBSERVATORY_MOZILLA_API = 'https://tls-observatory.services.mozilla.com/api/v1';
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  try {
    const domain = new URL(url).hostname;

    const scanResponse = await axios.post(`${TLS_OBSERVATORY_MOZILLA_API}/scan`, null, {
      params: { target: domain }
    });

    const { scan_id: scanId } = scanResponse.data;

    if (typeof scanId !== 'number') {
      throw new Error('Failed to get scan_id from TLS Observatory');
    }

    const resultResponse = await axios.get(`${TLS_OBSERVATORY_MOZILLA_API}/results`, {
      params: { id: scanId }
    });

    res.json(resultResponse.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ports
router.get('/port-scan', async (req, res) => {
  const PORTS = [
    20, 21, 22, 23, 25, 53, 80, 67, 68, 69,
    110, 119, 123, 143, 156, 161, 162, 179, 194,
    389, 443, 587, 993, 995,
    3000, 3306, 3389, 5060, 5900, 8000, 8080, 8888
  ];

  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  const domain = new URL(url).hostname;

  const openPorts = [];
  const failedPorts = [];

  const checkPort = (port, domain) => {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();

      socket.setTimeout(1500);

      socket.on('connect', () => {
        socket.destroy();
        resolve(port);
      });

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error(`Timeout at port: ${port}`));
      });

      socket.on('error', (e) => {
        socket.destroy();
        reject(e);
      });

      socket.connect(port, domain);
    });
  };

  const scanPorts = async () => {
    const promises = PORTS.map(port => checkPort(port, domain)
      .then(() => openPorts.push(port))
      .catch(() => failedPorts.push(port))
    );

    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Function timed out')), 9000)
    );

    try {
      await Promise.race([Promise.all(promises), timeoutPromise]);
    } catch (error) {
      if (error.message === 'Function timed out') {
        const scannedPorts = [...openPorts, ...failedPorts];
        const unscannedPorts = PORTS.filter(port => !scannedPorts.includes(port));
        failedPorts.push(...unscannedPorts);
      }
    }
  };

  await scanPorts();

  res.json({ openPorts, failedPorts });
});

// firewall
router.get('/firewall', async (req, res) => {

  const hasWaf = (waf) => {
    return {
      hasWaf: true, 
      waf,
    };
  };  

  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  const fullUrl = url.startsWith('http') ? url : `http://${url}`;

  try {
    const response = await axios.get(fullUrl);
    const headers = response.headers;

    if (headers['server'] && headers['server'].includes('cloudflare')) {
      return res.json(hasWaf('Cloudflare'));
    }

    if (headers['x-powered-by'] && headers['x-powered-by'].includes('AWS Lambda')) {
      return res.json(hasWaf('AWS WAF'));
    }

    if (headers['server'] && headers['server'].includes('AkamaiGHost')) {
      return res.json(hasWaf('Akamai'));
    }

    if (headers['server'] && headers['server'].includes('Sucuri')) {
      return res.json(hasWaf('Sucuri'));
    }

    if (headers['server'] && headers['server'].includes('BarracudaWAF')) {
      return res.json(hasWaf('Barracuda WAF'));
    }

    if (headers['server'] && (headers['server'].includes('F5 BIG-IP') || headers['server'].includes('BIG-IP'))) {
      return res.json(hasWaf('F5 BIG-IP'));
    }

    if (headers['x-sucuri-id'] || headers['x-sucuri-cache']) {
      return res.json(hasWaf('Sucuri CloudProxy WAF'));
    }

    if (headers['server'] && headers['server'].includes('FortiWeb')) {
      return res.json(hasWaf('Fortinet FortiWeb WAF'));
    }

    if (headers['server'] && headers['server'].includes('Imperva')) {
      return res.json(hasWaf('Imperva SecureSphere WAF'));
    }

    if (headers['x-protected-by'] && headers['x-protected-by'].includes('Sqreen')) {
      return res.json(hasWaf('Sqreen'));
    }

    if (headers['x-waf-event-info']) {
      return res.json(hasWaf('Reblaze WAF'));
    }

    if (headers['set-cookie'] && headers['set-cookie'].includes('_citrix_ns_id')) {
      return res.json(hasWaf('Citrix NetScaler'));
    }

    if (headers['x-denied-reason'] || headers['x-wzws-requested-method']) {
      return res.json(hasWaf('WangZhanBao WAF'));
    }

    if (headers['x-webcoment']) {
      return res.json(hasWaf('Webcoment Firewall'));
    }

    if (headers['server'] && headers['server'].includes('Yundun')) {
      return res.json(hasWaf('Yundun WAF'));
    }

    if (headers['x-yd-waf-info'] || headers['x-yd-info']) {
      return res.json(hasWaf('Yundun WAF'));
    }

    if (headers['server'] && headers['server'].includes('Safe3WAF')) {
      return res.json(hasWaf('Safe3 Web Application Firewall'));
    }

    if (headers['server'] && headers['server'].includes('NAXSI')) {
      return res.json(hasWaf('NAXSI WAF'));
    }

    if (headers['x-datapower-transactionid']) {
      return res.json(hasWaf('IBM WebSphere DataPower'));
    }

    return res.json({ hasWaf: false });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// trace-route
router.get('/traceroute', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }

  try {
    // Parse the URL and get the hostname
    const urlObject = new URL(url);
    const host = urlObject.hostname;

    if (!host) {
      throw new Error('Invalid URL provided');
    }

    // Perform traceroute with a promise
    const result = await new Promise((resolve, reject) => {
      traceroute.trace(host, (err, hops) => {
        if (err || !hops) {
          reject(err || new Error('No hops found'));
        } else {
          resolve(hops);
        }
      });
    });

    res.json({
      message: "Traceroute completed!",
      result,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// threats
router.get('/threats',async (req,res)=>{})

module.exports = router;
