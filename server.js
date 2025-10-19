// 1. MODULE IMPORTS
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const path = require('path');
const fs = require('fs');

// ☁️ BACKBLAZE B2/S3 IMPORTS (UPDATED)
const { S3Client, DeleteObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner'); // ✨ NEW IMPORT for Pre-Signing URLs
const multerS3 = require('multer-s3');

// SECURITY IMPORTS
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 🖼️ FILE UPLOAD IMPORT
const multer = require('multer');

// 📧 EMAIL IMPORT
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET


// ☁️ BACKBLAZE B2/S3 CONFIGURATION
const B2_ENDPOINT = process.env.B2_ENDPOINT;
const B2_KEY_ID = process.env.B2_KEY_ID;
const B2_APPLICATION_KEY = process.env.B2_APPLICATION_KEY;
const B2_BUCKET_NAME = process.env.B2_BUCKET_NAME;
const B2_REGION = process.env.B2_REGION;


// 1. Initialize the S3 Client for Backblaze B2
const s3 = new S3Client({
    endpoint: B2_ENDPOINT,
    region: B2_REGION,
    credentials: {
        accessKeyId: B2_KEY_ID,
        secretAccessKey: B2_APPLICATION_KEY,
    }
});

// 2. Define the Multer-S3 Storage
const s3Storage = multerS3({
    s3: s3,
    bucket: B2_BUCKET_NAME,
    // acl: 'public-read', // Keep this commented out for private bucket security
    metadata: function (req, file, cb) {
        cb(null, { fieldName: file.fieldname });
    },
    key: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const fileExtension = path.extname(file.originalname);
        const key = file.fieldname + '-' + uniqueSuffix + fileExtension;
        cb(null, key);
    }
});


// 🖼️ FILE UPLOAD SETUP (Multer with S3 Storage)

// 🖼️ Multer Instance for Admin Winner Image (Image only, 5MB limit)
const upload = multer({
    storage: s3Storage,
    limits: { fileSize: 1024 * 1024 * 5 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image')) {
            cb(null, true);
        } else {
            cb(new Error('Not an image! Please upload only images.'), false);
        }
    }
});

// 🖼️ NEW Multer Instance for General Registration Form (Allows more types, higher limit for files)
const generalUpload = multer({
    storage: s3Storage,
    limits: { fileSize: 1024 * 1024 * 10 },
    // No fileFilter here to allow PDF/other file types often used for ID verification
});


// 2. MIDDLEWARE
app.use(cors());
app.use(express.json());

// 🚨 CRITICAL STATIC FILE FIXES:
// 1. Explicitly serve the root index.html first.
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. Serve all other static assets from the project root directory.
app.use(express.static(__dirname));

// 3. Serve the 'admin' folder assets via a prefixed path (e.g., /admin/admin-login.html)
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'admin-login.html'));
});

// 4. Serve assets used *by* files inside the admin folder (e.g., admin/style.css)
app.use('/admin', express.static(path.join(__dirname, 'admin')));


// 3. MONGODB CONNECTION
const mongoUri = process.env.MONGODB_URI

mongoose.connect(mongoUri)
    .then(() => {
        console.log('✅ MongoDB connected successfully.');
    })
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        console.log('⚠️ WARNING: DB connection failed, but server will continue to start.');
    });
// 4. MONGODB SCHEMAS AND MODELS

// --- Admin User Schema and Model (NEW) ---
const AdminUserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    resetToken: { type: String, default: null }
});

AdminUserSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    next();
});

const AdminUser = mongoose.model('AdminUser', AdminUserSchema);


// --- Winner Schema and Model (UPDATED FOR CURRENCY) ---
const WinnerSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    location: { type: String, required: true, trim: true },
    code: { type: String, required: true, unique: true, trim: true },
    social: { type: String, default: '', trim: true },
    amount: { type: Number, required: true, min: 0 },
    // 💰 NEW FIELD for Winning Amount Currency
    currency: { type: String, required: true, trim: true, default: '$', maxlength: 4 },
    fee: { type: Number, required: true, min: 0 },
    // 💰 NEW FIELD for Payment Fee Currency
    feeCurrency: { type: String, required: true, trim: true, default: '$', maxlength: 4 },
    status: { type: String, required: true, trim: true },
    imageUrl: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
}, {
    timestamps: true
});

const Winner = mongoose.model('Winner', WinnerSchema);


// 5. AUTHENTICATION MIDDLEWARE (NEW)
/**
 * Middleware to protect routes. Checks for a valid JWT in the Authorization header.
 */
const protect = (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];

            const decoded = jwt.verify(token, JWT_SECRET);

            req.user = decoded.id;
            next();
        } catch (error) {
            console.error(error);
            return res.status(401).json({ message: 'Not authorized, token failed.' });
        }
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized, no token.' });
    }
};

// 6. AUTHENTICATION ROUTES (NEW)
// All auth routes will be prefixed with /api/auth
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        let user = await AdminUser.findOne({ email });

        if (user) {
            return res.status(400).json({ message: 'Admin account already exists.' });
        }

        user = await AdminUser.create({ email, password });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            message: 'Admin account created successfully.',
            token,
            email: user.email,
        });

    } catch (err) {
        if (err.name === 'ValidationError') {
            return res.status(400).json({ message: 'Validation failed.', errors: err.errors });
        }
        res.status(500).json({ message: 'Server error during registration.', error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await AdminUser.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            message: 'Login successful.',
            token,
            email: user.email,
        });

    } catch (err) {
        res.status(500).json({ message: 'Server error during login.', error: err.message });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await AdminUser.findOne({ email });
        if (!user) {
            return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
        }

        // This is a placeholder response
        res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });

    } catch (err) {
        res.status(500).json({ message: 'Server error during password reset request.', error: err.message });
    }
});

// 📧 Nodemailer Transport Setup
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_PORT === '465',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});


// 7. API ROUTES - General Form Submission (PUBLIC ROUTE)
// This route is NOT protected by the 'protect' middleware.
app.post('/submit-form', generalUpload.fields([
    { name: 'government_id_front', maxCount: 1 },
    { name: 'government_id_back', maxCount: 1 },
    { name: 'selfie_photo', maxCount: 1 }
]), async (req, res) => {

    const recipientEmail = process.env.EMAIL_USER; // Send applications to the admin email
    const formData = req.body;
    // req.files now contains the S3 key and other metadata, not local paths
    const uploadedFiles = req.files;

    // Helper to delete files from Backblaze B2
    const cleanupFiles = async () => {
        const filesToCleanup = [
            uploadedFiles.government_id_front?.[0],
            uploadedFiles.government_id_back?.[0],
            uploadedFiles.selfie_photo?.[0]
        ].filter(f => f);

        for (const file of filesToCleanup) {
            try {
                // Delete the file from B2 using its key
                const deleteParams = {
                    Bucket: B2_BUCKET_NAME,
                    Key: file.key // The 'key' is the file path on B2
                };
                await s3.send(new DeleteObjectCommand(deleteParams));
                // console.log(`Deleted file from B2: ${file.key}`); // Optional log
            } catch (error) {
                console.error(`Failed to delete B2 file ${file.key}:`, error.message);
                // Continue execution even if cleanup fails
            }
        }
    };


    try {
        // 1. Format Form Data for Email
        const needsList = Array.isArray(formData.needs)
            ? formData.needs.map(n => `* ${n.replace(/_/g, ' ')}`).join('\n')
            : (formData.needs ? `* ${formData.needs.replace(/_/g, ' ')}` : 'None specified');

        const platforms = formData.social_platform || [];
        const handles = formData.social_handle || [];
        const socialHandles = platforms.map((platform, index) => {
            return platform && handles[index] ? `- ${platform.toUpperCase()}: ${handles[index]}` : '';
        }).filter(s => s).join('\n');

        // 2. Prepare Attachments Array (NOW USES B2 STREAMS)
        const attachments = [];

        // Function to create an S3 stream attachment object
        const createS3Attachment = (fileArray, filenamePrefix) => {
            if (fileArray && fileArray[0]) {
                const file = fileArray[0];
                // Use GetObjectCommand to stream the file directly from B2
                const s3Stream = s3.send(new GetObjectCommand({
                    Bucket: B2_BUCKET_NAME,
                    Key: file.key, // Use the B2 key
                })).then(response => response.Body); // Get the readable stream

                attachments.push({
                    filename: `${filenamePrefix}_${file.originalname}`,
                    content: s3Stream, // Nodemailer streams content from S3/B2
                });
            }
        };

        createS3Attachment(uploadedFiles.government_id_front, 'ID_Front');
        createS3Attachment(uploadedFiles.government_id_back, 'ID_Back');
        createS3Attachment(uploadedFiles.selfie_photo, 'Selfie');


        // 3. Send Email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: recipientEmail,
            subject: `New Grant Application: ${formData.first_name} ${formData.last_name}`,
            // ENHANCED HTML TEMPLATE START
            html: `
                <div style="background-color: #f4f7f6; padding: 20px; font-family: 'Inter', Arial, sans-serif; color: #333; line-height: 1.6;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">

                        <div style="background-color: #00796B; color: #ffffff; padding: 20px 30px;">
                            <h1 style="margin: 0; font-size: 24px;">New Grant Application</h1>
                            <p style="margin: 5px 0 0 0; font-size: 14px; opacity: 0.9;">
                                Application from: <strong>${formData.first_name} ${formData.middle_name || ''} ${formData.last_name}</strong>
                            </p>
                        </div>

                        <div style="padding: 25px 30px;">

                            <h3 style="color: #00796B; border-bottom: 2px solid #e0f2f1; padding-bottom: 5px; margin-top: 0;">Contact & Location</h3>
                            <table width="100%" border="0" cellspacing="0" cellpadding="0" style="font-size: 14px;">
                                <tr>
                                    <td width="50%" style="padding: 4px 0;"><strong style="color: #555;">Email:</strong> <a href="mailto:${formData.email}" style="color: #00796B;">${formData.email}</a></td>
                                    <td width="50%" style="padding: 4px 0;"><strong style="color: #555;">Phone:</strong> ${formData.text_number}</td>
                                </tr>
                                <tr>
                                    <td colspan="2" style="padding-top: 10px;">
                                        <p style="margin: 0;"><strong style="color: #555;">Address:</strong></p>
                                        <p style="margin: 0 0 5px 0;">${formData.street_address}<br>
                                        ${formData.city}, ${formData.state} ${formData.zip_code}<br>
                                        ${formData.country}</p>
                                    </td>
                                </tr>
                            </table>

                            <h3 style="color: #00796B; border-bottom: 2px solid #e0f2f1; padding-bottom: 5px; margin-top: 20px;">Requested Needs</h3>
                            <pre style="background: #e0f2f1; color: #004d40; padding: 15px; border: 1px solid #b2dfdb; border-radius: 8px; white-space: pre-wrap; word-break: break-word;">${needsList}</pre>

                            <h3 style="color: #00796B; border-bottom: 2px solid #e0f2f1; padding-bottom: 5px; margin-top: 20px;">Personal & Financial Details</h3>
                            <table width="100%" border="0" cellspacing="0" cellpadding="0" style="font-size: 14px;">
                                <tr>
                                    <td width="50%" style="padding: 4px 0;"><strong style="color: #555;">DOB:</strong> ${formData.dob}</td>
                                    <td width="50%" style="padding: 4px 0;"><strong style="color: #555;">Sex:</strong> ${formData.sex}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 4px 0;"><strong style="color: #555;">Occupation:</strong> ${formData.occupation}</td>
                                    <td style="padding: 4px 0;"><strong style="color: #555;">Education:</strong> ${formData.education_level}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 4px 0;"><strong style="color: #555;">Residency:</strong> ${formData.residency}</td>
                                    <td style="padding: 4px 0;"><strong style="color: #555;">Payment Method:</strong> ${formData.payment_method}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 4px 0;"><strong style="color: #555;">Monthly Income:</strong> ${formData.currency_symbol} ${formData.monthly_income}</td>
                                    <td style="padding: 4px 0;"><strong style="color: #555;">Heard Via:</strong> ${formData.how_heard}</td>
                                </tr>
                                <tr>
                                    <td colspan="2" style="padding: 4px 0;"><strong style="color: #555;">Disability:</strong> ${formData.physical_challenges}${formData.disability_description ? ` (${formData.disability_description})` : ''}</td>
                                </tr>
                            </table>

                            ${socialHandles.length > 0 ? `
                            <h3 style="color: #00796B; border-bottom: 2px solid #e0f2f1; padding-bottom: 5px; margin-top: 20px;">Social Handles</h3>
                            <pre style="background: #e0f2f1; color: #004d40; padding: 15px; border: 1px solid #b2dfdb; border-radius: 8px; white-space: pre-wrap; word-break: break-word;">${socialHandles}</pre>
                            ` : ''}

                            <div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee;">
                                <p style="font-size: 14px; color: #777; text-align: center; margin: 0;">
                                    <strong style="color: #D32F2F;">ACTION REQUIRED:</strong>
                                    <br>Attachments for identity verification (ID Front/Back & Selfie) are included with this email. These files have been **deleted from the cloud storage** after being sent for security.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            `
            // ENHANCED HTML TEMPLATE END
            ,
            attachments: attachments
        });

        // 4. Cleanup: Delete files from B2 after successful email send
        await cleanupFiles();

        return res.status(200).json({ message: 'Application submitted and email sent successfully! The uploaded files have been securely deleted from cloud storage.' });

    } catch (error) {
        console.error('Submission/Nodemailer Error:', error);

        // 5. Cleanup: Delete files from B2 even if email fails
        await cleanupFiles();

        return res.status(500).json({ message: 'Application failed to process or send email notification.', error: error.message });
    }
});


// 🖼️ 7.0. POST /api/upload - Handle Image Upload (Admin route for winner images)
app.post('/api/upload', protect, (req, res) => {
    // 1. Wrap the Multer middleware call in a handler
    upload.single('winnerImage')(req, res, (err) => {
        // 2. Check for Multer-specific errors
        if (err instanceof multer.MulterError) {
            console.error('Multer Error on /api/upload:', err.code, err.message);
            return res.status(400).json({ message: `Upload failed: ${err.message}` });
        }
        // 3. Check for other non-Multer, synchronous errors (like your fileFilter error)
        if (err) {
            console.error('General Upload Error:', err);
            // Return a 500 status with the specific error message to help debugging
            return res.status(500).json({ message: `Image processing error: ${err.message}` });
        }

        // 4. Proceed with successful upload logic
        try {
            if (!req.file) {
                return res.status(400).json({ message: 'No file uploaded or file was rejected by filter.' });
            }
            
            // ✅ FIX: The s3Storage key function stores the path in req.file.key, not req.file.location.
            // We must store the object's Key (path) and not the full public URL, which is unauthorized.
            const imageKey = req.file.key; 

            res.json({
                message: 'Image uploaded successfully to B2.',
                imageUrl: imageKey // Store the B2 Key (path), not the unauthorized URL
            });
        } catch (syncErr) {
            // 5. Catch any synchronous errors that happened after Multer finished
            console.error('Error in /api/upload handler logic:', syncErr);
            res.status(500).json({ message: 'Internal server error after successful upload.', error: syncErr.message });
        }
    });
});


// --- Helper function for fetching dashboard stats ---
async function getDashboardStats() {
    const total = await Winner.countDocuments();
    const published = await Winner.countDocuments({ status: { $in: ['published', 'featured'] } });
    const draft = await Winner.countDocuments({ status: 'draft' });
    return { total, published, draft };
}

// 7.1. GET /api/winners/stats - Fetch Dashboard Statistics
app.get('/api/winners/stats', protect, async (req, res) => {
    try {
        const stats = await getDashboardStats();
        res.json(stats);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching stats.', error: err.message });
    }
});

// 7.2. GET /api/winners - Read All Winners (for table view)
// 🟢 FIX: Generate Pre-Signed URLs for the private images here.
app.get('/api/winners', async (req, res) => {
    try {
        // 1. Fetch all winners
        const winners = await Winner.find().sort({ createdAt: -1 });

        // 2. Map winners to include the Pre-Signed URL for the image
        const winnersWithSignedUrls = await Promise.all(
            winners.map(async (winner) => {
                let signedUrl = winner.imageUrl; // Default to the stored value (which is now the Key)

                // Only generate a signed URL if an image key exists
                if (winner.imageUrl) {
                    try {
                        const command = new GetObjectCommand({
                            Bucket: B2_BUCKET_NAME,
                            Key: winner.imageUrl, // The stored image key/path
                        });

                        // 🔑 Generate the temporary, time-limited URL (5 minutes)
                        signedUrl = await getSignedUrl(s3, command, { expiresIn: 300 }); // 300 seconds = 5 minutes
                    } catch (err) {
                        console.error(`Error generating signed URL for key ${winner.imageUrl}:`, err.message);
                        // Fallback to empty string if the file is missing or an error occurs
                        signedUrl = '';
                    }
                }

                // Return the winner data with the updated imageUrl
                return {
                    ...winner.toObject(),
                    imageUrl: signedUrl,
                };
            })
        );

        res.json(winnersWithSignedUrls);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching winners.', error: err.message });
    }
});

// 7.3. POST /api/winners - Create a new Winner Profile
app.post('/api/winners', protect, async (req, res) => {
    try {
        const newWinner = new Winner(req.body);
        const savedWinner = await newWinner.save();
        res.status(201).json(savedWinner);
    } catch (err) {
        if (err.name === 'ValidationError' || (err.code === 11000 && err.keyPattern && err.keyPattern.code === 1)) {
            let message = 'Validation failed.';
            if (err.code === 11000) message = 'A winner with that code already exists.';
            return res.status(400).json({ message, errors: err.errors || err.errmsg });
        }
        res.status(500).json({ message: 'Error creating winner.', error: err.message });
    }
});

// 7.4. PUT /api/winners/:id - Update an existing Winner Profile
app.put('/api/winners/:id', protect, async (req, res) => {
    try {
        const updatedWinner = await Winner.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true, runValidators: true }
        );

        if (!updatedWinner) {
            return res.status(404).json({ message: 'Winner not found.' });
        }
        res.json(updatedWinner);
    } catch (err) {
        if (err.name === 'ValidationError' || (err.code === 11000 && err.keyPattern && err.keyPattern.code === 1)) {
             let message = 'Validation failed.';
            if (err.code === 11000) message = 'A winner with that code already exists.';
            return res.status(400).json({ message, errors: err.errors || err.errmsg });
        }
        res.status(500).json({ message: 'Error updating winner.', error: err.message });
    }
});

// 7.5. DELETE /api/winners/:id - Delete a Winner Record
app.delete('/api/winners/:id', protect, async (req, res) => {
    try {
        const result = await Winner.findByIdAndDelete(req.params.id);

        if (!result) {
            return res.status(404).json({ message: 'Winner not found.' });
        }
        res.json({ message: 'Winner deleted successfully.' });
    } catch (err) {
        res.status(500).json({ message: 'Error deleting winner.', error: err.message });
    }
});


// 8. START SERVER
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}. Access http://localhost:${PORT}`);
    console.log(`💡 Dependencies check complete.`);
});