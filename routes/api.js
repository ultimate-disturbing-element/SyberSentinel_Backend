const express =  require('express');
const cors = require("cors");
const dns = require('dns');

const router = express.Router();

// Get Ip Address
router.get('/get-ip/',(req, res) => {
    const {url} = req.query; 
    try {
    const address = url.replace('https://', '').replace('http://', '');  
     // Perform DNS lookup for the modified address
     dns.lookup(address, (err, ip, family) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to perform DNS lookup.' });
        }
        // Send the response with IP address and family
        res.json({ url, ip, family });
    });
    }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});



module.exports = router;