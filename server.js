const express = require('express');
const cors = require('cors');
const apiRouter = require('./routes/api')
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Enable CORS
app.use(cors({
    origin: process.env.API_CORS_ORIGIN || '*',
}));

app.use(express.json());

// Mount the /api router
app.use('/api', apiRouter);

// Print a nice welcome message to the user
const printMessage = () => {
    console.log(
        `SyberSentinel is up and running at http://localhost:${port}`,
    );
};

// Start the server
app.listen(port, () => {
    printMessage();
});
