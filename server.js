// 1. MODULE IMPORTS
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors'); 
require('dotenv').config(); 
const path = require('path');
const fs = require('fs'); // Core Node module for file system operations

// SECURITY IMPORTS
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 

// 🖼️ FILE UPLOAD IMPORT
const multer = require('multer'); 

// 📧 EMAIL IMPORT
const nodemailer = require('nodemailer'); 

const app = express();
// FIX 1: Use the host-defined PORT, but keep a fallback (5000) for local testing, 
// as omitting it completely can lead to issues if the variable isn't set as expected.
const PORT = process.env.PORT || 5000; 
const JWT_SECRET = process.env.JWT_SECRET 


// 🖼️ FILE UPLOAD SETUP (Multer)
// Define storage for ALL uploads (admin winners and general forms)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // Create an 'uploads' directory in the project root if it doesn't exist
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        // Ensure unique filename: originalname + timestamp + extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const fileExtension = path.extname(file.originalname);
        // file.fieldname will be the input's name attribute (e.g., 'winnerImage', 'government_id_front')
        cb(null, file.fieldname + '-' + uniqueSuffix + fileExtension);
    }
});

// 🖼️ Multer Instance for Admin Winner Image (Image only, 5MB limit)
const upload = multer({ 
    storage: storage,
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
    storage: storage,
    limits: { fileSize: 1024 * 1024 * 10 }, // 10MB limit for multiple ID/Selfie files
    // No fileFilter here to allow PDF/other file types often used for ID verification
});


// 2. MIDDLEWARE
app.use(cors()); 
app.use(express.json()); 

// 🚨 CRITICAL STATIC FILE FIXES:
// 1. Explicitly serve the root index.html first.
app.get('/', (req, res) => {
    // This explicitly serves the main public page located in the project root.
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. Serve all other static assets from the project root directory.
// FIX 2: Use __dirname directly. This is the absolute, most robust way to serve files 
// from the project root. It handles files like registrationform.html, CSS, JS, etc.
app.use(express.static(__dirname));

// 3. Serve the 'admin' folder assets via a prefixed path (e.g., /admin/admin-login.html)
// This must be done BEFORE the prefixed static route for assets inside 'admin'
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'admin-login.html'));
});

// 4. Serve assets used *by* files inside the admin folder (e.g., admin/style.css)
app.use('/admin', express.static(path.join(__dirname, 'admin')));


// 5. Serve uploaded files statically from the 'uploads' folder via the /uploads route
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// 3. MONGODB CONNECTION
const mongoUri = process.env.MONGODB_URI

mongoose.connect(mongoUri)
    .then(() => {
        console.log('✅ MongoDB connected successfully.');
    })
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        // The 502 error is gone, confirming this was the original crash cause. 
        // Keep commented out for now, but ensure MongoDB Atlas IP Access is set to 0.0.0.0/0.
        // process.exit(1); 
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
    // Using .env variables for security and easy configuration
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT, 
    // FIX: Environment variables are strings. Use strict comparison to check the port string.
    secure: process.env.EMAIL_PORT === '465', 
    auth: {
        user: process.env.EMAIL_USER, // The email address that sends the application
        pass: process.env.EMAIL_PASS, // The app password for that email
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
    const uploadedFiles = req.files;

    // Helper to clean up files if an error occurs
    const cleanupFiles = () => {
        if (uploadedFiles.government_id_front) fs.unlink(uploadedFiles.government_id_front[0].path, () => {});
        if (uploadedFiles.government_id_back) fs.unlink(uploadedFiles.government_id_back[0].path, () => {});
        if (uploadedFiles.selfie_photo) fs.unlink(uploadedFiles.selfie_photo[0].path, () => {});
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

        // 2. Prepare Attachments Array
        const attachments = [];
        
        // Add file paths to attachments array
        if (uploadedFiles.government_id_front) {
            attachments.push({
                filename: `ID_Front_${uploadedFiles.government_id_front[0].originalname}`,
                path: uploadedFiles.government_id_front[0].path
            });
        }
        if (uploadedFiles.government_id_back) {
            attachments.push({
                filename: `ID_Back_${uploadedFiles.government_id_back[0].originalname}`,
                path: uploadedFiles.government_id_back[0].path
            });
        }
        if (uploadedFiles.selfie_photo) {
            attachments.push({
                filename: `Selfie_${uploadedFiles.selfie_photo[0].originalname}`,
                path: uploadedFiles.selfie_photo[0].path
            });
        }

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
                                    <br>Attachments for identity verification (ID Front/Back & Selfie) are included with this email. Please review files and delete them manually from the server storage after processing.
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
        
        // 4. Cleanup: Delete temporary files after successful email send
        cleanupFiles();

        return res.status(200).json({ message: 'Application submitted and email sent successfully!' });

    } catch (error) {
        console.error('Submission/Nodemailer Error:', error);
        
        // 5. Cleanup: Delete files even if email fails
        cleanupFiles(); 

        return res.status(500).json({ message: 'Application failed to process or send email notification.', error: error.message });
    }
});

// 7. PROTECTED API ROUTES (CRUD IMPLEMENTATION)

// 🖼️ 7.0. POST /api/upload - Handle Image Upload (Admin route for winner images)
app.post('/api/upload', protect, upload.single('winnerImage'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded.' });
        }
        
        // The path.join('/', req.file.path).replace(/\\/g, '/') ensures correct URL path
        const relativeUrl = path.join('/', req.file.path).replace(/\\/g, '/');

        res.json({
            message: 'Image uploaded successfully.',
            imageUrl: relativeUrl 
        });
    } catch (err) {
        res.status(500).json({ message: 'Error uploading file.', error: err.message });
    }
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
// 🟢 PUBLIC ROUTE: 'protect' middleware has been REMOVED here!
app.get('/api/winners', async (req, res) => {
    try {
        const winners = await Winner.find().sort({ createdAt: -1 });
        res.json(winners);
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