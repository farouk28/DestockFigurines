const port = 4000;
const express = require("express");
const session = require('express-session');
const mongoose = require("mongoose");
const MongoStore = require('connect-mongo');
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require('fs');
const path = require("path");
const cors = require("cors");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const app = express();

// Session Middleware Setup
app.use(session({
    secret: 'your_secret_key', // Replace with a strong secret
    resave: false,
    saveUninitialized: true,
    store:MongoStore.create({ 
        mongoUrl: "mongodb+srv://Farouk:Naruto12@cluster0.jjsmv.mongodb.net/e-commerce"}),
    cookie: { secure: false } // Set to true if using HTTPS in production
}));

app.use(express.json());
app.use(cors());
app.use(passport.initialize());
app.use(passport.session());

// Database Connection with MongoDB
mongoose.connect("mongodb+srv://Farouk:Naruto12@cluster0.jjsmv.mongodb.net/e-commerce");

// Start the server
app.listen(port, (error) => {
    if (!error) {
        console.log("Server Running on Port " + port);
    } else {
        console.log("Error: " + error);
    }
});

// Image Storage Engine
const storage = multer.diskStorage({
    // Utilisez le répertoire temporaire /tmp
    destination: (req, file, cb) => {
        cb(null, '/tmp'); // Répertoire writable
    },
    filename: (req, file, cb) => {
        // Créez un nom de fichier unique avec un horodatage
        cb(null, `${file.fieldname}_${Date.now()}${path.extname(file.originalname)}`);
    }
});

// Initialiser multer avec la configuration de stockage
const upload = multer({ storage: storage });

// Endpoint pour le téléchargement d'images
app.post('/upload', upload.single('image'), (req, res) => {
    // Vérifiez si le fichier a été téléchargé
    if (!req.file) {
        return res.status(400).json({ success: 0, message: 'Aucun fichier téléchargé.' });
    }

    // Créer un répertoire pour stocker les images si nécessaire
    const uploadPath = path.join(__dirname, 'upload', 'images');
    if (!fs.existsSync(uploadPath)) {
        fs.mkdirSync(uploadPath, { recursive: true });
    }

    // Définir les chemins pour le fichier temporaire et la cible
    const tempPath = path.join('/tmp', req.file.filename);
    const targetPath = path.join(uploadPath, req.file.filename);

    // Déplacer le fichier du répertoire temporaire vers le répertoire d'images
    fs.rename(tempPath, targetPath, (err) => {
        if (err) {
            console.error('Erreur lors du déplacement du fichier:', err);
            return res.status(500).json({ success: 0, message: 'Erreur lors du déplacement du fichier.' });
        }

        // Répondre avec l'URL de l'image téléchargée
        res.json({
            success: 1,
            image_url: `http://localhost:${port}/images/${req.file.filename}`
        });
    });
});

// Créer un endpoint pour servir les images
app.use('/images', express.static(path.join(__dirname, 'upload', 'images')));


// Schema for Creating Products
const Product = mongoose.model("Product", {
    id: { type: Number, required: true },
    name: { type: String, required: true },
    image: { type: String, required: true },
    category: { type: String, required: true },
    new_price: { type: Number, required: true },
    old_price: { type: Number, required: true },
    date: { type: Date, default: Date.now },
    available: { type: Boolean, default: true },
});

// Schema creation for User model
const Users = mongoose.model('Users', {
    name: { type: String },
    email: { type: String, unique: true },
    password: { type: String },
    cartData: { type: Object },
    date: { type: Date, default: Date.now },
});

// Add Product Endpoint
app.post('/addproduct', async (req, res) => {
    const products = await Product.find({});
    const id = products.length > 0 ? products[products.length - 1].id + 1 : 1;

    const product = new Product({
        id: id,
        name: req.body.name,
        image: req.body.image,
        category: req.body.category,
        new_price: req.body.new_price,
        old_price: req.body.old_price,
    });

    await product.save();
    res.json({ success: true, name: req.body.name });
});

// Creating Endpoint for registering the user
app.post('/signup', async (req, res) => {
    const check = await Users.findOne({ email: req.body.email });
    if (check) {
        return res.status(400).json({ success: false, errors: "Existing user found with the same email address" });
    }
    
    let cart = {};
    for (let i = 0; i < 300; i++) {
        cart[i] = 0; // Initialize the cart data
    }
    
    const user = new Users({
        name: req.body.username,
        email: req.body.email,
        password: req.body.password, // Consider hashing the password before saving
        cartData: cart,
    });

    await user.save();

    const data = {
        user: {
            id: user.id
        }
    };

    const token = jwt.sign(data, 'secret_ecom');
    res.json({ success: true, token });
});

// Creating endpoint for user login
app.post('/login', async (req, res) => {
    const user = await Users.findOne({ email: req.body.email });
    if (user) {
        const passCompare = req.body.password === user.password; // Hash comparison is recommended
        if (passCompare) {
            const data = {
                user: {
                    id: user.id
                }
            };
            const token = jwt.sign(data, 'secret_ecom');
            res.json({ success: true, token });
        } else {
            res.json({ success: false, errors: "Wrong Password" });
        }
    } else {
        res.json({ success: false, errors: "Wrong Email Id" });
    }
});

// Creating API For deleting Products
app.post('/removeproduct', async (req, res) => {
    await Product.findOneAndDelete({ id: req.body.id });
    res.json({ success: true });
});

// Creating API for getting all products
app.get('/allproducts', async (req, res) => {
    const products = await Product.find({});
    res.send(products);
});

// Creating API for updating products
app.patch('/updateproduct/:id', async (req, res) => {
    try {
        const updateProduct = await Product.findByIdAndUpdate(req.params.id, req.body, {
            new: true,
            runValidators: true
        });
        res.status(200).json({
            status: "success",
            data: {
                product: updateProduct
            }
        });
    } catch (error) {
        res.status(404).json({
            status: "fail",
            message: error.message
        });
    }
});

// Creating API for getting all users
app.get('/allusers', async (req, res) => {
    const users = await Users.find({});
    res.send(users);
});

// Creating API For deleting Users
app.post('/removeuser', async (req, res) => {
    await Users.findOneAndDelete({ _id: req.body.id });
    res.json({ success: true });
});

// Creating API For Updating Users
app.patch('/updateuser/:_id', async (req, res) => {
    try {
        const updateUser  = await Users.findByIdAndUpdate(req.params._id, req.body, {
            new: true,
            runValidators: true
        });
        res.status(200).json({
            status: "success",
            data: {
                user: updateUser 
            }
        });
    } catch (error) {
        res.status(404).json({ status: "fail", message: error.message });
    }
});

// API for frontend user update
app.put("/profileupdate", async (req, res) => {
    try {
        const { username, email, password, newPassword, confirmPassword } = req.body;
        const user = await Users.findById(req.user._id);

        if (!user) {
            return res.status(404).json({ message: "User  not found" });
        }

        if (password !== user.password) { // Password comparison should use hashing
            return res.status(401).json({ message: "Incorrect password" });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        user.name = username;
        user.email = email;
        user.password = newPassword; // Hash the new password before saving

        await user.save();

        res.json({ success: true, message: "Profile updated successfully" });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

// Middleware to fetch user
const fetchUser  = async (req, res, next) => {
    const token = req.header('auth-token');
    if (!token) {
        return res.status(401).send({ errors: "Please authenticate using a valid token" });
    }
    try {
        const data = jwt.verify(token, 'secret_ecom');
        req.user = data.user;
        next();
    } catch (error) {
        res.status(401).send({ errors: "Please authenticate using a valid token" });
    }
};

// Creating endpoint for adding products in cart data
app.post('/addtocart', fetchUser , async (req, res) => {
    const userData = await Users.findOne({ _id: req.user.id });
    userData.cartData[req.body.itemId] += 1;
    await Users.findOneAndUpdate({ _id: req.user.id }, { cartData: userData.cartData });
    res.send("Added to cart");
});

// Creating endpoint to remove product from cart data
app.post('/removefromcart', fetchUser , async (req, res) => {
    const userData = await Users.findOne({ _id: req.user.id });
    if (userData.cartData[req.body.itemId] > 0) {
        userData.cartData[req.body.itemId] -= 1;
    }
    await Users.findOneAndUpdate({ _id: req.user.id }, { cartData: userData.cartData });
    res.send("Removed from cart");
});

// Creating endpoint to get cart data
app.post('/getcart', fetchUser , async (req, res) => {
    const userData = await Users.findOne({ _id: req.user.id });
    res.json(userData.cartData);
});

// Creating endpoint for new collections data
app.get('/newcollections', async (req, res) => {
    const products = await Product.find({});
    const newCollection = products.slice(-8); // Get the last 8 products
    res.send(newCollection);
});

// Creating endpoint for popular items in a specific category
app.get('/popularinonepiece', async (req, res) => {
    const products = await Product.find({ category: "onepiece" });
    const popularInOnePiece = products.slice(0, 4); // Get the first 4 products
    res.send(popularInOnePiece);
});