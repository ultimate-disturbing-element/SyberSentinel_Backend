const express = require("express");
const net = require('net');
const psl = require('psl');
const axios = require('axios');
const dns = require("dns");
const tls = require("tls");

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
        return res.status(500).json({ error: "Failed to perform DNS lookup." });
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

module.exports = router;
