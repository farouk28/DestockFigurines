require('dotenv').config();
const express = require("express");
const session = require('express-session');
const mongoose = require("mongoose");
const MongoStore = require('connect-mongo');
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require('fs');
const path = require("path");
const cors = require("cors");
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const winston = require('winston');
const passport = require("passport");

// Initialisation de l'app
const app = express();
const port = process.env.PORT || 4000;

// Configuration du logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

// Middleware de sécurité
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS.split(','),
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limite par IP
});
app.use(limiter);

// Configuration des sessions
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24 // 24 heures
    }
}));

app.use(express.json());
app.use(passport.initialize());
app.use(passport.session());

// Connexion à la base de données
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    logger.info('Connected to MongoDB');
}).catch((error) => {
    logger.error('MongoDB connection error:', error);
});

// Configuration du stockage des fichiers
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, '/tmp');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// Configuration de Multer avec validation des types de fichiers
const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
        const error = new Error('Type de fichier non supporté');
        error.code = 'LIMIT_FILE_TYPES';
        return cb()
    }}

// Suite de la configuration Multer
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB max
    }
});

// Modèles de données
const productSchema = new mongoose.Schema({
    id: { type: Number, required: true },
    name: { type: String, required: true, trim: true },
    image: { type: String, required: true },
    category: { type: String, required: true },
    new_price: { type: Number, required: true },
    old_price: { type: Number, required: true },
    date: { type: Date, default: Date.now },
    available: { type: Boolean, default: true }
});

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    cartData: { type: Map, of: Number, default: new Map() },
    date: { type: Date, default: Date.now },
    resetPasswordToken: String,
    resetPasswordExpires: Date
});

const Product = mongoose.model("Product", productSchema);
const Users = mongoose.model('Users', userSchema);

// Middleware d'authentification
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.header('Authorization');
        if (!authHeader) {
            return res.status(401).json({ error: 'Accès non autorisé' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (error) {
        logger.error('Authentication error:', error);
        res.status(401).json({ error: 'Token invalide' });
    }
};

// Validation des données
const validateProduct = [
    body('name').trim().notEmpty().withMessage('Le nom est requis'),
    body('price').isNumeric().withMessage('Le prix doit être un nombre'),
    body('category').trim().notEmpty().withMessage('La catégorie est requise')
];

const validateUser = [
    body('email').isEmail().normalizeEmail().withMessage('Email invalide'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Le mot de passe doit contenir au moins 8 caractères')
        .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])/)
        .withMessage('Le mot de passe doit contenir au moins une majuscule, une minuscule et un chiffre')
];

// Routes pour la gestion des images
app.post('/upload', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Aucun fichier téléchargé' });
        }

        const uploadPath = path.join(__dirname, 'upload', 'images');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }

        const tempPath = req.file.path;
        const targetPath = path.join(uploadPath, req.file.filename);

        await fs.promises.rename(tempPath, targetPath);

        res.json({
            success: true,
            image_url: `${req.protocol}://${req.get('host')}/images/${req.file.filename}`
        });
    } catch (error) {
        logger.error('Upload error:', error);
        res.status(500).json({ error: 'Erreur lors du téléchargement' });
    }
});

// Routes d'authentification (suite)
app.post('/signup', validateUser, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password, username } = req.body;
        
        // Vérifier si l'utilisateur existe déjà
        const existingUser = await Users.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Cet email est déjà utilisé' });
        }

        // Hasher le mot de passe
        const hashedPassword = await bcrypt.hash(password, 12);

        // Créer un nouveau utilisateur
        const user = new Users({
            name: username,
            email,
            password: hashedPassword,
            cartData: new Map()
        });

        await user.save();

        // Générer le token JWT
        const token = jwt.sign(
            { user: { id: user._id } },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({ success: true, token });
    } catch (error) {
        logger.error('Signup error:', error);
        res.status(500).json({ error: 'Erreur lors de l\'inscription' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Trouver l'utilisateur
        const user = await Users.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        // Vérifier le mot de passe
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        // Générer le token
        const token = jwt.sign(
            { user: { id: user._id } },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ success: true, token });
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({ error: 'Erreur lors de la connexion' });
    }
});

// Routes des produits
app.post('/addproduct', authenticateToken, validateProduct, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const products = await Product.find({});
        const id = products.length > 0 ? Math.max(...products.map(p => p.id)) + 1 : 1;

        const product = new Product({
            id,
            ...req.body
        });

        await product.save();
        res.status(201).json({ success: true, product });
    } catch (error) {
        logger.error('Add product error:', error);
        res.status(500).json({ error: 'Erreur lors de l\'ajout du produit' });
    }
});

app.get('/allproducts', async (req, res) => {
    try {
        const products = await Product.find({})
            .select('-__v')
            .sort({ date: -1 });
        res.json(products);
    } catch (error) {
        logger.error('Get products error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des produits' });
    }
});

// Suite de la route de mise à jour des produits
app.patch('/updateproduct/:id', authenticateToken, validateProduct, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const product = await Product.findByIdAndUpdate(
            req.params.id,
            { $set: req.body },
            { new: true, runValidators: true }
        );

        if (!product) {
            return res.status(404).json({ error: 'Produit non trouvé' });
        }

        res.json({ success: true, product });
    } catch (error) {
        logger.error('Update product error:', error);
        res.status(500).json({ error: 'Erreur lors de la mise à jour du produit' });
    }
});

// Gestion du panier
app.post('/cart/add', authenticateToken, async (req, res) => {
    try {
        const { productId, quantity = 1 } = req.body;
        
        // Vérifier si le produit existe
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ error: 'Produit non trouvé' });
        }

        // Mettre à jour le panier de l'utilisateur
        const user = await Users.findById(req.user.id);
        const currentQuantity = user.cartData.get(productId) || 0;
        user.cartData.set(productId, currentQuantity + quantity);
        
        await user.save();
        
        res.json({ success: true, message: 'Produit ajouté au panier' });
    } catch (error) {
        logger.error('Add to cart error:', error);
        res.status(500).json({ error: 'Erreur lors de l\'ajout au panier' });
    }
});

app.post('/cart/remove', authenticateToken, async (req, res) => {
    try {
        const { productId, quantity = 1 } = req.body;
        
        const user = await Users.findById(req.user.id);
        const currentQuantity = user.cartData.get(productId) || 0;
        
        if (currentQuantity <= quantity) {
            user.cartData.delete(productId);
        } else {
            user.cartData.set(productId, currentQuantity - quantity);
        }
        
        await user.save();
        
        res.json({ success: true, message: 'Produit retiré du panier' });
    } catch (error) {
        logger.error('Remove from cart error:', error);
        res.status(500).json({ error: 'Erreur lors du retrait du panier' });
    }
});

app.get('/cart', authenticateToken, async (req, res) => {
    try {
        const user = await Users.findById(req.user.id);
        const cartItems = [];
        
        for (const [productId, quantity] of user.cartData) {
            const product = await Product.findById(productId);
            if (product) {
                cartItems.push({
                    product,
                    quantity
                });
            }
        }
        
        res.json(cartItems);
    } catch (error) {
        logger.error('Get cart error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération du panier' });
    }
});

// Routes pour les collections et produits populaires (suite)
app.get('/collections/popular/:category', async (req, res) => {
    try {
        const { category } = req.params;
        const popularProducts = await Product.find({ category })
            .sort({ views: -1 })
            .limit(4)
            .select('-__v');
            
        res.json(popularProducts);
    } catch (error) {
        logger.error('Get popular products error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des produits populaires' });
    }
});

// Gestion du profil utilisateur
app.get('/profile', authenticateToken, async (req, res) => {
    try {
        const user = await Users.findById(req.user.id)
            .select('-password -__v');
        if (!user) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }
        res.json(user);
    } catch (error) {
        logger.error('Get profile error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération du profil' });
    }
});

app.put('/profile', authenticateToken, validateUser, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, currentPassword, newPassword } = req.body;
        const user = await Users.findById(req.user.id);

        if (newPassword) {
            // Vérifier l'ancien mot de passe
            const isValidPassword = await bcrypt.compare(currentPassword, user.password);
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
            }
            // Hasher le nouveau mot de passe
            user.password = await bcrypt.hash(newPassword, 12);
        }

        user.name = username || user.name;
        user.email = email || user.email;

        await user.save();
        res.json({ success: true, message: 'Profil mis à jour avec succès' });
    } catch (error) {
        logger.error('Update profile error:', error);
        res.status(500).json({ error: 'Erreur lors de la mise à jour du profil' });
    }
});

// Gestion des commandes
app.post('/orders', authenticateToken, async (req, res) => {
    try {
        const user = await Users.findById(req.user.id);
        const cartItems = [];
        let totalAmount = 0;

        // Récupérer les produits du panier et calculer le montant total
        for (const [productId, quantity] of user.cartData) {
            const product = await Product.findById(productId);
            if (product) {
                cartItems.push({
                    product: productId,
                    quantity,
                    price: product.new_price
                });
                totalAmount += product.new_price * quantity;
            }
        }

        // Créer la commande
        const order = new Order({
            user: req.user.id,
            items: cartItems,
            totalAmount,
            shippingAddress: req.body.shippingAddress,
            status: 'pending'
        });

        await order.save();

        // Vider le panier
        user.cartData = new Map();
        await user.save();

        res.status(201).json({ success: true, order });
    } catch (error) {
        logger.error('Create order error:', error);
        res.status(500).json({ error: 'Erreur lors de la création de la commande' });
    }
});

// Middleware de gestion des erreurs (suite)
app.use((err, req, res, next) => {
    logger.error('Error:', err);
    
    if (err instanceof ValidationError) {
        return res.status(400).json({
            error: 'Erreur de validation',
            details: err.errors
        });
    }

    if (err instanceof UnauthorizedError) {
        return res.status(401).json({
            error: 'Non autorisé',
            message: err.message
        });
    }

    res.status(500).json({
        error: 'Erreur serveur',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Une erreur est survenue'
    });
});

// Middleware pour la pagination
const paginateResults = (model) => {
    return async (req, res, next) => {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const startIndex = (page - 1) * limit;
        
        try {
            const total = await model.countDocuments();
            const data = await model.find()
                .limit(limit)
                .skip(startIndex)
                .exec();

            res.pagination = {
                currentPage: page,
                itemsPerPage: limit,
                totalItems: total,
                totalPages: Math.ceil(total / limit),
                data
            };
            
            next();
        } catch (error) {
            next(error);
        }
    };
};

// Routes avec pagination
app.get('/products', paginateResults(Product), (req, res) => {
    res.json(res.pagination);
});

// Middleware pour le filtrage
const filterResults = (allowedFields) => {
    return (req, res, next) => {
        const filters = {};
        
        Object.keys(req.query).forEach(key => {
            if (allowedFields.includes(key)) {
                filters[key] = req.query[key];
            }
        });
        
        req.filters = filters;
        next();
    };
};

// Routes avec filtrage
app.get('/products/filter', 
    filterResults(['category', 'price_min', 'price_max']),
    async (req, res, next) => {
        try {
            const query = {};
            
            if (req.filters.category) {
                query.category = req.filters.category;
            }
            
            if (req.filters.price_min || req.filters.price_max) {
                query.new_price = {};
                if (req.filters.price_min) {
                    query.new_price.$gte = parseFloat(req.filters.price_min);
                }
                if (req.filters.price_max) {
                    query.new_price.$lte = parseFloat(req.filters.price_max);
                }
            }
            
            const products = await Product.find(query);
            res.json(products);
        } catch (error) {
            next(error);
        }
    }
);

// Middleware pour la mise en cache
const cache = (duration) => {
    const cacheData = new Map();
    
    return (req, res, next) => {
        const key = req.originalUrl;
        const cachedResponse = cacheData.get(key);
        
        if (cachedResponse && Date.now() - cachedResponse.timestamp < duration) {
            return res.json(cachedResponse.data);
        }
        
        res.originalJson = res.json;
        res.json = (data) => {
            cacheData.set(key, {
                timestamp: Date.now(),
                data
            });
            res.originalJson(data);
        };
        
        next();
    };
};

// Routes avec mise en cache (suite)
app.get('/popular-products', cache(300000), async (req, res) => {
    try {
        const popularProducts = await Product.find()
            .sort({ views: -1 })
            .limit(10);
        res.json(popularProducts);
    } catch (error) {
        next(error);
    }
});

// Système de recherche
app.get('/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) {
            return res.status(400).json({ error: 'Paramètre de recherche requis' });
        }

        const searchResults = await Product.find({
            $or: [
                { name: { $regex: q, $options: 'i' } },
                { category: { $regex: q, $options: 'i' } }
            ]
        }).limit(20);

        res.json(searchResults);
    } catch (error) {
        logger.error('Search error:', error);
        res.status(500).json({ error: 'Erreur lors de la recherche' });
    }
});

// Système de notation et avis
const Review = mongoose.model('Review', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String },
    date: { type: Date, default: Date.now }
});

app.post('/products/:productId/reviews', authenticateToken, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const { productId } = req.params;

        // Vérifier si l'utilisateur a déjà laissé un avis
        const existingReview = await Review.findOne({
            user: req.user.id,
            product: productId
        });

        if (existingReview) {
            return res.status(400).json({ error: 'Vous avez déjà laissé un avis pour ce produit' });
        }

        const review = new Review({
            user: req.user.id,
            product: productId,
            rating,
            comment
        });

        await review.save();

        // Mettre à jour la note moyenne du produit
        const reviews = await Review.find({ product: productId });
        const averageRating = reviews.reduce((acc, curr) => acc + curr.rating, 0) / reviews.length;

        await Product.findByIdAndUpdate(productId, { averageRating });

        res.status(201).json({ success: true, review });
    } catch (error) {
        logger.error('Review creation error:', error);
        res.status(500).json({ error: 'Erreur lors de la création de l\'avis' });
    }
});

// Système de favoris
app.post('/favorites/toggle', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.body;
        const user = await Users.findById(req.user.id);

        if (!user.favorites) {
            user.favorites = [];
        }

        const index = user.favorites.indexOf(productId);
        if (index === -1) {
            user.favorites.push(productId);
        } else {
            user.favorites.splice(index, 1);
        }

        await user.save();
        res.json({ success: true, favorites: user.favorites });
    } catch (error) {
        logger.error('Toggle favorite error:', error);
        res.status(500).json({ error: 'Erreur lors de la gestion des favoris' });
    }
});

// Système de notifications (suite)
const Notification = mongoose.model('Notification', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    type: { type: String, required: true }, // 'order', 'product', 'promotion', etc.
    message: { type: String, required: true },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

// Obtenir les notifications d'un utilisateur
app.get('/notifications', authenticateToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ user: req.user.id })
            .sort({ createdAt: -1 })
            .limit(20);
        res.json(notifications);
    } catch (error) {
        logger.error('Get notifications error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des notifications' });
    }
});

// Marquer une notification comme lue
app.patch('/notifications/:id/read', authenticateToken, async (req, res) => {
    try {
        const notification = await Notification.findOneAndUpdate(
            { _id: req.params.id, user: req.user.id },
            { read: true },
            { new: true }
        );
        
        if (!notification) {
            return res.status(404).json({ error: 'Notification non trouvée' });
        }
        
        res.json(notification);
    } catch (error) {
        logger.error('Mark notification read error:', error);
        res.status(500).json({ error: 'Erreur lors de la mise à jour de la notification' });
    }
});

// Système de promotions et codes promo
const Promotion = mongoose.model('Promotion', {
    code: { type: String, required: true, unique: true },
    type: { type: String, enum: ['percentage', 'fixed'], required: true },
    value: { type: Number, required: true },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    minimumPurchase: { type: Number, default: 0 },
    usageLimit: { type: Number },
    usedCount: { type: Number, default: 0 }
});

// Vérifier la validité d'un code promo
app.post('/promotions/verify', authenticateToken, async (req, res) => {
    try {
        const { code, cartTotal } = req.body;
        
        const promotion = await Promotion.findOne({
            code,
            startDate: { $lte: new Date() },
            endDate: { $gte: new Date() },
            usageLimit: { $gt: 0 }
        });

        if (!promotion) {
            return res.status(400).json({ error: 'Code promo invalide ou expiré' });
        }

        if (cartTotal < promotion.minimumPurchase) {
            return res.status(400).json({ 
                error: `Montant minimum d'achat requis: ${promotion.minimumPurchase}€`
            });
        }

        const discount = promotion.type === 'percentage' 
            ? (cartTotal * promotion.value / 100)
            : promotion.value;

        res.json({
            valid: true,
            discount,
            finalTotal: cartTotal - discount
        });
    } catch (error) {
        logger.error('Verify promotion error:', error);
        res.status(500).json({ error: 'Erreur lors de la vérification du code promo' });
    }
});

// Système de recommandations (suite)
app.get('/recommendations', authenticateToken, async (req, res) => {
    try {
        const user = await Users.findById(req.user.id);
        const userOrders = await Order.find({ user: req.user.id });
        
        // Récupérer les catégories préférées basées sur l'historique d'achats
        const preferredCategories = userOrders
            .flatMap(order => order.products)
            .reduce((acc, product) => {
                acc[product.category] = (acc[product.category] || 0) + 1;
                return acc;
            }, {});

        // Trouver des produits similaires
        const recommendations = await Product.find({
            category: { $in: Object.keys(preferredCategories) },
            _id: { $nin: userOrders.flatMap(order => order.products.map(p => p._id)) }
        })
        .sort({ averageRating: -1 })
        .limit(10);

        res.json(recommendations);
    } catch (error) {
        logger.error('Recommendations error:', error);
        res.status(500).json({ error: 'Erreur lors de la génération des recommandations' });
    }
});

// Système de commandes
const Order = mongoose.model('Order', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    products: [{
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        quantity: Number,
        price: Number
    }],
    totalAmount: Number,
    status: {
        type: String,
        enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'],
        default: 'pending'
    },
    shippingAddress: {
        street: String,
        city: String,
        postalCode: String,
        country: String
    },
    paymentMethod: String,
    paymentStatus: {
        type: String,
        enum: ['pending', 'completed', 'failed'],
        default: 'pending'
    },
    createdAt: { type: Date, default: Date.now }
});

// Créer une nouvelle commande
app.post('/orders', authenticateToken, async (req, res) => {
    try {
        const { products, shippingAddress, paymentMethod } = req.body;

        // Vérifier le stock et calculer le montant total
        let totalAmount = 0;
        const orderProducts = [];

        for (const item of products) {
            const product = await Product.findById(item.productId);
            if (!product || !product.available) {
                return res.status(400).json({ 
                    error: `Le produit ${product.name} n'est plus disponible` 
                });
            }

            orderProducts.push({
                product: product._id,
                quantity: item.quantity,
                price: product.new_price
            });

            totalAmount += product.new_price * item.quantity;
        }

        const order = new Order({
            user: req.user.id,
            products: orderProducts,
            totalAmount,
            shippingAddress,
            paymentMethod
        });

        await order.save();

        // Créer une notification pour l'utilisateur
        const notification = new Notification({
            user: req.user.id,
            type: 'order',
            message: `Votre commande #${order._id} a été créée avec succès.`
        });
        await notification.save();

        res.status(201).json(order);
    } catch (error) {
        logger.error('Order creation error:', error);
        res.status(500).json({ error: 'Erreur lors de la création de la commande' });
    }
});

// Obtenir l'historique des commandes (suite)
app.get('/orders', authenticateToken, async (req, res) => {
    try {
        const orders = await Order.find({ user: req.user.id })
            .populate('products.product')
            .sort({ createdAt: -1 });
        res.json(orders);
    } catch (error) {
        logger.error('Get orders error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des commandes' });
    }
});

// Obtenir les détails d'une commande spécifique
app.get('/orders/:orderId', authenticateToken, async (req, res) => {
    try {
        const order = await Order.findOne({
            _id: req.params.orderId,
            user: req.user.id
        }).populate('products.product');

        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        res.json(order);
    } catch (error) {
        logger.error('Get order details error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des détails de la commande' });
    }
});

// Annuler une commande
app.post('/orders/:orderId/cancel', authenticateToken, async (req, res) => {
    try {
        const order = await Order.findOne({
            _id: req.params.orderId,
            user: req.user.id,
            status: 'pending'
        });

        if (!order) {
            return res.status(404).json({ 
                error: 'Commande non trouvée ou ne peut plus être annulée' 
            });
        }

        order.status = 'cancelled';
        await order.save();

        // Créer une notification
        await new Notification({
            user: req.user.id,
            type: 'order',
            message: `Votre commande #${order._id} a été annulée.`
        }).save();

        res.json({ success: true, order });
    } catch (error) {
        logger.error('Cancel order error:', error);
        res.status(500).json({ error: 'Erreur lors de l\'annulation de la commande' });
    }
});

// Système de catégories
const Category = mongoose.model('Category', {
    name: { type: String, required: true, unique: true },
    description: String,
    image: String,
    parent: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
    isActive: { type: Boolean, default: true }
});

// Créer une nouvelle catégorie
app.post('/categories', authenticateToken, async (req, res) => {
    try {
        const { name, description, image, parentId } = req.body;
        
        const category = new Category({
            name,
            description,
            image,
            parent: parentId
        });

        await category.save();
        res.status(201).json(category);
    } catch (error) {
        logger.error('Create category error:', error);
        res.status(500).json({ error: 'Erreur lors de la création de la catégorie' });
    }
});

// Obtenir toutes les catégories
app.get('/categories', async (req, res) => {
    try {
        const categories = await Category.find({ isActive: true })
            .populate('parent')
            .sort({ name: 1 });
        res.json(categories);
    } catch (error) {
        logger.error('Get categories error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des catégories' });
    }
});

// Système de statistiques pour l'administration (suite)
app.get('/admin/statistics', authenticateToken, async (req, res) => {
    try {
        // Vérifier si l'utilisateur est administrateur
        const user = await Users.findById(req.user.id);
        if (!user.isAdmin) {
            return res.status(403).json({ error: 'Accès non autorisé' });
        }

        const today = new Date();
        const lastMonth = new Date(today.getFullYear(), today.getMonth() - 1, today.getDate());

        // Statistiques générales
        const stats = {
            totalUsers: await Users.countDocuments(),
            totalProducts: await Product.countDocuments(),
            totalOrders: await Order.countDocuments(),
            
            // Statistiques des commandes du dernier mois
            recentOrders: await Order.find({
                createdAt: { $gte: lastMonth }
            }).countDocuments(),

            // Chiffre d'affaires du mois
            monthlyRevenue: await Order.aggregate([
                {
                    $match: {
                        createdAt: { $gte: lastMonth },
                        status: { $in: ['processing', 'shipped', 'delivered'] }
                    }
                },
                {
                    $group: {
                        _id: null,
                        total: { $sum: "$totalAmount" }
                    }
                }
            ]),

            // Produits les plus vendus
            topProducts: await Order.aggregate([
                { $unwind: "$products" },
                {
                    $group: {
                        _id: "$products.product",
                        totalSold: { $sum: "$products.quantity" }
                    }
                },
                { $sort: { totalSold: -1 } },
                { $limit: 5 },
                {
                    $lookup: {
                        from: "products",
                        localField: "_id",
                        foreignField: "_id",
                        as: "productInfo"
                    }
                }
            ])
        };

        res.json(stats);
    } catch (error) {
        logger.error('Admin statistics error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des statistiques' });
    }
});

// Système de recherche avancée
app.get('/search', async (req, res) => {
    try {
        const { 
            query, 
            category, 
            minPrice, 
            maxPrice, 
            sortBy, 
            page = 1, 
            limit = 10 
        } = req.query;

        const searchCriteria = {};

        // Critères de recherche
        if (query) {
            searchCriteria.name = { $regex: query, $options: 'i' };
        }
        if (category) {
            searchCriteria.category = category;
        }
        if (minPrice || maxPrice) {
            searchCriteria.new_price = {};
            if (minPrice) searchCriteria.new_price.$gte = Number(minPrice);
            if (maxPrice) searchCriteria.new_price.$lte = Number(maxPrice);
        }

        // Options de tri
        const sortOptions = {};
        if (sortBy) {
            switch (sortBy) {
                case 'price_asc':
                    sortOptions.new_price = 1;
                    break;
                case 'price_desc':
                    sortOptions.new_price = -1;
                    break;
                case 'name_asc':
                    sortOptions.name = 1;
                    break;
                case 'name_desc':
                    sortOptions.name = -1;
                    break;
                default:
                    sortOptions.createdAt = -1;
            }
        }

        // Pagination
        const skip = (page - 1) * limit;

        const products = await Product.find(searchCriteria)
            .sort(sortOptions)
            .skip(skip)
            .limit(Number(limit));

        const total = await Product.countDocuments(searchCriteria);

        res.json({
            products,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            totalResults: total
        });
    } catch (error) {
        logger.error('Search error:', error);
        res.status(500).json({ error: 'Erreur lors de la recherche' });
    }
});

// Système de notifications
const Notification = mongoose.model('Notification', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users' },
    type: { type: String, enum: ['order', 'promotion', 'system'] },
    message: String,
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

// Obtenir les notifications de l'utilisateur
app.get('/notifications', authenticateToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ user: req.user.id })
            .sort({ createdAt: -1 })
            .limit(20);
        res.json(notifications);
    } catch (error) {
        logger.error('Get notifications error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des notifications' });
    }
});

// Marquer une notification comme lue
app.patch('/notifications/:notificationId', authenticateToken, async (req, res) => {
    try {
        const notification = await Notification.findOneAndUpdate(
            { _id: req.params.notificationId, user: req.user.id },
            { read: true },
            { new: true }
        );

        if (!notification) {
            return res.status(404).json({ error: 'Notification non trouvée' });
        }

        res.json(notification);
    } catch (error) {
        logger.error('Update notification error:', error);
        res.status(500).json({ error: 'Erreur lors de la mise à jour de la notification' });
    }
});

// Système de wishlist (liste de souhaits)
const Wishlist = mongoose.model('Wishlist', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    products: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
    createdAt: { type: Date, default: Date.now }
});

// Ajouter un produit à la wishlist
app.post('/wishlist/add', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.body;
        
        let wishlist = await Wishlist.findOne({ user: req.user.id });
        
        if (!wishlist) {
            wishlist = new Wishlist({
                user: req.user.id,
                products: [productId]
            });
        } else if (!wishlist.products.includes(productId)) {
            wishlist.products.push(productId);
        }

        await wishlist.save();
        res.json({ success: true, wishlist });
    } catch (error) {
        logger.error('Add to wishlist error:', error);
        res.status(500).json({ error: 'Erreur lors de l\'ajout à la wishlist' });
    }
});

// Supprimer un produit de la wishlist (suite)
app.delete('/wishlist/remove/:productId', authenticateToken, async (req, res) => {
    try {
        const wishlist = await Wishlist.findOneAndUpdate(
            { user: req.user.id },
            { $pull: { products: req.params.productId } },
            { new: true }
        ).populate('products');

        if (!wishlist) {
            return res.status(404).json({ error: 'Wishlist non trouvée' });
        }

        res.json({ success: true, wishlist });
    } catch (error) {
        logger.error('Remove from wishlist error:', error);
        res.status(500).json({ error: 'Erreur lors de la suppression de la wishlist' });
    }
});

// Obtenir la wishlist de l'utilisateur
app.get('/wishlist', authenticateToken, async (req, res) => {
    try {
        const wishlist = await Wishlist.findOne({ user: req.user.id })
            .populate('products');
        
        if (!wishlist) {
            return res.json({ products: [] });
        }

        res.json(wishlist);
    } catch (error) {
        logger.error('Get wishlist error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération de la wishlist' });
    }
});

// Système de reviews (avis)
const Review = mongoose.model('Review', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: String,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Ajouter une review
app.post('/products/:productId/reviews', authenticateToken, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        
        // Vérifier si l'utilisateur a déjà laissé une review
        const existingReview = await Review.findOne({
            user: req.user.id,
            product: req.params.productId
        });

        if (existingReview) {
            return res.status(400).json({ error: 'Vous avez déjà laissé un avis pour ce produit' });
        }

        const review = new Review({
            user: req.user.id,
            product: req.params.productId,
            rating,
            comment
        });

        await review.save();

        // Mettre à jour la note moyenne du produit
        const reviews = await Review.find({ product: req.params.productId });
        const averageRating = reviews.reduce((acc, curr) => acc + curr.rating, 0) / reviews.length;

        await Product.findByIdAndUpdate(req.params.productId, {
            $set: { averageRating }
        });

        res.status(201).json(review);
    } catch (error) {
        logger.error('Add review error:', error);
        res.status(500).json({ error: 'Erreur lors de l\'ajout de l\'avis' });
    }
});

// Obtenir les reviews d'un produit (suite)
app.get('/products/:productId/reviews', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const reviews = await Review.find({ product: req.params.productId })
            .populate('user', 'name')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Review.countDocuments({ product: req.params.productId });

        res.json({
            reviews,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            totalReviews: total
        });
    } catch (error) {
        logger.error('Get reviews error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des avis' });
    }
});

// Système de commandes
const Order = mongoose.model('Order', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    products: [{
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        quantity: Number,
        price: Number
    }],
    totalAmount: Number,
    shippingAddress: {
        street: String,
        city: String,
        state: String,
        postalCode: String,
        country: String
    },
    status: {
        type: String,
        enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'],
        default: 'pending'
    },
    paymentStatus: {
        type: String,
        enum: ['pending', 'completed', 'failed'],
        default: 'pending'
    },
    paymentMethod: String,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Créer une nouvelle commande
app.post('/orders', authenticateToken, async (req, res) => {
    try {
        const { products, shippingAddress, paymentMethod } = req.body;

        // Calculer le montant total
        let totalAmount = 0;
        const orderProducts = [];

        for (const item of products) {
            const product = await Product.findById(item.productId);
            if (!product) {
                return res.status(404).json({ error: `Produit ${item.productId} non trouvé` });
            }

            orderProducts.push({
                product: product._id,
                quantity: item.quantity,
                price: product.new_price
            });

            totalAmount += product.new_price * item.quantity;
        }

        const order = new Order({
            user: req.user.id,
            products: orderProducts,
            totalAmount,
            shippingAddress,
            paymentMethod
        });

        await order.save();

        // Créer une notification pour l'utilisateur
        const notification = new Notification({
            user: req.user.id,
            type: 'order',
            message: `Votre commande #${order._id} a été créée avec succès.`
        });
        await notification.save();

        res.status(201).json(order);
    } catch (error) {
        logger.error('Create order error:', error);
        res.status(500).json({ error: 'Erreur lors de la création de la commande' });
    }
});

// Obtenir les commandes de l'utilisateur (suite)
app.get('/orders', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const orders = await Order.find({ user: req.user.id })
            .populate('products.product')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Order.countDocuments({ user: req.user.id });

        res.json({
            orders,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            totalOrders: total
        });
    } catch (error) {
        logger.error('Get orders error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des commandes' });
    }
});

// Mettre à jour le statut d'une commande
app.patch('/orders/:orderId/status', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        const order = await Order.findOneAndUpdate(
            { _id: req.params.orderId, user: req.user.id },
            { 
                status,
                updatedAt: Date.now()
            },
            { new: true }
        );

        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        // Créer une notification pour le changement de statut
        const notification = new Notification({
            user: req.user.id,
            type: 'order',
            message: `Le statut de votre commande #${order._id} a été mis à jour en "${status}".`
        });
        await notification.save();

        res.json(order);
    } catch (error) {
        logger.error('Update order status error:', error);
        res.status(500).json({ error: 'Erreur lors de la mise à jour du statut de la commande' });
    }
});

// Système de catégories
const Category = mongoose.model('Category', {
    name: { type: String, required: true, unique: true },
    description: String,
    image: String,
    parentCategory: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Créer une nouvelle catégorie
app.post('/categories', authenticateToken, async (req, res) => {
    try {
        const { name, description, image, parentCategory } = req.body;

        const category = new Category({
            name,
            description,
            image,
            parentCategory
        });

        await category.save();
        res.status(201).json(category);
    } catch (error) {
        logger.error('Create category error:', error);
        res.status(500).json({ error: 'Erreur lors de la création de la catégorie' });
    }
});

// Obtenir toutes les catégories
app.get('/categories', async (req, res) => {
    try {
        const categories = await Category.find({ active: true })
            .populate('parentCategory')
            .sort({ name: 1 });

        res.json(categories);
    } catch (error) {
        logger.error('Get categories error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des catégories' });
    }
});

// Système de promotions (suite)
const Promotion = mongoose.model('Promotion', {
    code: { type: String, required: true, unique: true },
    type: { type: String, enum: ['percentage', 'fixed_amount'], required: true },
    value: { type: Number, required: true },
    minPurchase: { type: Number, default: 0 },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    usageLimit: { type: Number, default: null },
    usedCount: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    applicableProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
    applicableCategories: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Category' }]
});

// Créer une nouvelle promotion
app.post('/promotions', authenticateToken, async (req, res) => {
    try {
        const {
            code,
            type,
            value,
            minPurchase,
            startDate,
            endDate,
            usageLimit,
            applicableProducts,
            applicableCategories
        } = req.body;

        const promotion = new Promotion({
            code,
            type,
            value,
            minPurchase,
            startDate,
            endDate,
            usageLimit,
            applicableProducts,
            applicableCategories
        });

        await promotion.save();
        res.status(201).json(promotion);
    } catch (error) {
        logger.error('Create promotion error:', error);
        res.status(500).json({ error: 'Erreur lors de la création de la promotion' });
    }
});

// Vérifier la validité d'un code promo
app.post('/promotions/verify', authenticateToken, async (req, res) => {
    try {
        const { code, cartTotal, products } = req.body;
        const now = new Date();

        const promotion = await Promotion.findOne({
            code,
            active: true,
            startDate: { $lte: now },
            endDate: { $gte: now }
        });

        if (!promotion) {
            return res.status(404).json({ error: 'Code promotion invalide ou expiré' });
        }

        if (promotion.usageLimit && promotion.usedCount >= promotion.usageLimit) {
            return res.status(400).json({ error: 'Le code promotion a atteint sa limite d\'utilisation' });
        }

        if (cartTotal < promotion.minPurchase) {
            return res.status(400).json({ 
                error: `Le montant minimum d'achat doit être de ${promotion.minPurchase}€`
            });
        }

        // Calculer la réduction
        let discount = 0;
        if (promotion.type === 'percentage') {
            discount = (cartTotal * promotion.value) / 100;
        } else {
            discount = promotion.value;
        }

        res.json({
            valid: true,
            discount,
            promotion
        });
    } catch (error) {
        logger.error('Verify promotion error:', error);
        res.status(500).json({ error: 'Erreur lors de la vérification du code promotion' });
    }
});

// Système de notifications
const Notification = mongoose.model('Notification', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    type: { 
        type: String, 
        enum: ['order', 'promotion', 'system'], 
        required: true 
    },
    message: { type: String, required: true },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

// Obtenir les notifications de l'utilisateur (suite)
app.get('/notifications', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const notifications = await Notification.find({ user: req.user.id })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const unreadCount = await Notification.countDocuments({
            user: req.user.id,
            read: false
        });

        const total = await Notification.countDocuments({ user: req.user.id });

        res.json({
            notifications,
            unreadCount,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            totalNotifications: total
        });
    } catch (error) {
        logger.error('Get notifications error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des notifications' });
    }
});

// Marquer les notifications comme lues
app.post('/notifications/mark-read', authenticateToken, async (req, res) => {
    try {
        const { notificationIds } = req.body;

        await Notification.updateMany(
            {
                _id: { $in: notificationIds },
                user: req.user.id
            },
            { read: true }
        );

        res.json({ success: true });
    } catch (error) {
        logger.error('Mark notifications read error:', error);
        res.status(500).json({ error: 'Erreur lors de la mise à jour des notifications' });
    }
});

// Système de wishlist
const Wishlist = mongoose.model('Wishlist', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    products: [{ 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Product' 
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Ajouter un produit à la wishlist
app.post('/wishlist/add', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.body;

        let wishlist = await Wishlist.findOne({ user: req.user.id });

        if (!wishlist) {
            wishlist = new Wishlist({
                user: req.user.id,
                products: [productId]
            });
        } else if (!wishlist.products.includes(productId)) {
            wishlist.products.push(productId);
            wishlist.updatedAt = Date.now();
        }

        await wishlist.save();
        res.json(wishlist);
    } catch (error) {
        logger.error('Add to wishlist error:', error);
        res.status(500).json({ error: 'Erreur lors de l\'ajout à la wishlist' });
    }
});

// Retirer un produit de la wishlist
app.post('/wishlist/remove', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.body;

        const wishlist = await Wishlist.findOne({ user: req.user.id });

        if (!wishlist) {
            return res.status(404).json({ error: 'Wishlist non trouvée' });
        }

        wishlist.products = wishlist.products.filter(
            product => product.toString() !== productId
        );
        wishlist.updatedAt = Date.now();

        await wishlist.save();
        res.json(wishlist);
    } catch (error) {
        logger.error('Remove from wishlist error:', error);
        res.status(500).json({ error: 'Erreur lors du ret'})
    }
})

// Obtenir la wishlist de l'utilisateur
app.get('/wishlist', authenticateToken, async (req, res) => {
    try {
        let wishlist = await Wishlist.findOne({ user: req.user.id })
            .populate('products');

        if (!wishlist) {
            wishlist = new Wishlist({ user: req.user.id, products: [] });
            await wishlist.save();
        }

        res.json(wishlist);
    } catch (error) {
        logger.error('Get wishlist error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération de la wishlist' });
    }
});

// Système de reviews et ratings
const Review = mongoose.model('Review', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    title: { type: String, required: true },
    comment: { type: String, required: true },
    images: [String],
    verified_purchase: { type: Boolean, default: false },
    helpful_votes: { type: Number, default: 0 },
    reported: { type: Boolean, default: false },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Créer une nouvelle review
app.post('/reviews', authenticateToken, async (req, res) => {
    try {
        const { productId, rating, title, comment, images } = req.body;

        // Vérifier si l'utilisateur a déjà laissé une review pour ce produit
        const existingReview = await Review.findOne({
            user: req.user.id,
            product: productId
        });

        if (existingReview) {
            return res.status(400).json({ error: 'Vous avez déjà laissé une review pour ce produit' });
        }

        // Vérifier si l'utilisateur a acheté le produit
        const hasOrdered = await Order.findOne({
            user: req.user.id,
            'products.product': productId,
            status: 'delivered'
        });

        const review = new Review({
            user: req.user.id,
            product: productId,
            rating,
            title,
            comment,
            images,
            verified_purchase: !!hasOrdered
        });

        await review.save();

        // Mettre à jour la moyenne des ratings du produit
        const reviews = await Review.find({ 
            product: productId,
            status: 'approved'
        });
        
        const averageRating = reviews.reduce((acc, curr) => acc + curr.rating, 0) / reviews.length;
        
        await Product.findByIdAndUpdate(productId, {
            $set: { average_rating: averageRating }
        });

        res.status(201).json(review);
    } catch (error) {
        logger.error('Create review error:', error);
        res.status(500).json({ error: 'Erreur lors de la création de la review' });
    }
});

// Obtenir les reviews d'un produit
app.get('/products/:productId/reviews', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const sort = req.query.sort || 'recent'; // recent, helpful, rating_high, rating_low
        const skip = (page - 1) * limit;

        let sortOption = {};
        switch (sort) {
            case 'helpful':
                sortOption = { helpful_votes: -1 };
                break;
            case 'rating_high':
                sortOption = { rating: -1 };
                break;
            case 'rating_low':
                sortOption = { rating: 1 };
                break;
            default:
                sortOption = { createdAt: -1 };
        }

        const reviews = await Review.find({
            product: req.params.productId,
            status: 'approved'
        })
            .populate('user', 'name')
            .sort(sortOption)
            .skip(skip)
            .limit(limit);

        const total = await Review.countDocuments({
            product: req.params.productId,
            status: 'approved'
        });

        // Calculer les statistiques des reviews
        const stats = await Review.aggregate([
            {
                $match: {
                    product: mongoose.Types.ObjectId(req.params.productId),
                    status: 'approved'
                }
            },
            {
                $group: {
                    _id: '$rating',
                    count: { $sum: 1 }
                }
            }
        ]);

        const ratingStats = {
            5: 0, 4: 0, 3: 0, 2: 0, 1: 0,
            ...Object.fromEntries(stats.map(s => [s._id, s.count]))
        };

        res.json({
            reviews,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
            totalReviews: total,
            ratingStats
        });
    } catch (error) {
        logger.error('Get reviews error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des reviews' });
    }
});

// Voter pour une review utile
app.post('/reviews/:reviewId/vote', authenticateToken, async (req, res) => {
try {
const review = await Review.findById(req.params.reviewId);

if (!review) {
    return res.status(404).json({ error: 'Review non trouvée' });
}

review.helpful_votes += 1;
await review.save();

res.json({ success: true, helpful_votes: review.helpful_votes });
} catch (error) {
logger.error('Vote review error:', error);
res.status(500).json({ error: 'Erreur lors du vote' });
}
});

// Signaler une review
app.post('/reviews/:reviewId/report', authenticateToken, async (req, res) => {
try {
const { reason } = req.body;
const review = await Review.findById(req.params.reviewId);

if (!review) {
    return res.status(404).json({ error: 'Review non trouvée' });
}

review.reported = true;
await review.save();

// Créer une notification pour les administrateurs
const notification = new Notification({
    type: 'system',
    message: `Review ${review._id} signalée. Raison: ${reason}`,
    // Envoyer à tous les admins
});
await notification.save();

res.json({ success: true });
} catch (error) {
logger.error('Report review error:', error);
res.status(500).json({ error: 'Erreur lors du signalement' });
}
});

// Système de recherche avancée
app.get('/search', async (req, res) => {
try {
    const {
        query,
        category,
        minPrice,
        maxPrice,
        rating,
        sortBy,
        page = 1,
        limit = 12
    } = req.query;

    // Construire les critères de recherche
    let searchCriteria = {};
    
    if (query) {
        searchCriteria.name = { $regex: query, $options: 'i' };
    }
    
    if (category) {
        searchCriteria.category = category;
    }
    
    if (minPrice || maxPrice) {
        searchCriteria.new_price = {};
        if (minPrice) searchCriteria.new_price.$gte = Number(minPrice);
        if (maxPrice) searchCriteria.new_price.$lte = Number(maxPrice);
    }
    
    if (rating) {
        searchCriteria.average_rating = { $gte: Number(rating) };
    }

    // Options de tri
    let sortOptions = {};
    switch (sortBy) {
        case 'price_asc':
            sortOptions.new_price = 1;
            break;
        case 'price_desc':
            sortOptions.new_price = -1;
            break;
        case 'rating':
            sortOptions.average_rating = -1;
            break;
        case 'newest':
            sortOptions.date = -1;
            break;
        default:
            sortOptions.date = -1;
    }

    const skip = (page - 1) * limit;

    // Exécuter la recherche
    const products = await Product.find(searchCriteria)
        .sort(sortOptions)
        .skip(skip)
        .limit(limit);

    const total = await Product.countDocuments(searchCriteria);

    res.json({
        products,
        currentPage: Number(page),
        totalPages: Math.ceil(total / limit),
        totalProducts: total
    });
} catch (error) {
    logger.error('Search error:', error);
    res.status(500).json({ error: 'Erreur lors de la recherche' });
}
});

// Système de recommandations
app.get('/recommendations', authenticateToken, async (req, res) => {
try {
    // Obtenir l'historique des achats de l'utilisateur
    const userOrders = await Order.find({ user: req.user.id })
        .populate('products.product');

    // Extraire les catégories préférées
    const categoryFrequency = {};
    userOrders.forEach(order => {
        order.products.forEach(item => {
            const category = item.product.category;
            categoryFrequency[category] = (categoryFrequency[category] || 0) + 1;
        });
    });

    // Trier les catégories par fréquence
    const preferredCategories = Object.entries(categoryFrequency)
        .sort((a, b) => b[1] - a[1])
        .map(entry => entry[0])
        .slice(0, 3);

    // Obtenir les produits recommandés
    const recommendations = await Product.aggregate([
        {
            $match: {
                category: { $in: preferredCategories },
                available: true
            }
        },
        {
            $sample: { size: 10 }
        }
    ]);

    res.json(recommendations);
} catch (error) {
    logger.error('Recommendations error:', error);
    res.status(500).json({ error: 'Erreur lors de la génération des recommandations' });
}
});

// Suite du schéma Promotion
const Promotion = mongoose.model('Promotion', {
    code: { type: String, required: true, unique: true },
    type: { type: String, enum: ['percentage', 'fixed'], required: true },
    value: { type: Number, required: true },
    minPurchase: { type: Number, default: 0 },
    maxDiscount: { type: Number }, // Pour les réductions en pourcentage
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    usageLimit: { type: Number }, // Nombre total d'utilisations permises
    userLimit: { type: Number, default: 1 }, // Nombre d'utilisations par utilisateur
    usageCount: { type: Number, default: 0 },
    categories: [String], // Catégories éligibles
    products: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }], // Produits éligibles
    active: { type: Boolean, default: true }
});

// Vérifier un code promo
app.post('/verify-promo', authenticateToken, async (req, res) => {
    try {
        const { code, cartTotal, items } = req.body;

        const promotion = await Promotion.findOne({
            code: code.toUpperCase(),
            active: true,
            startDate: { $lte: new Date() },
            endDate: { $gte: new Date() }
        });

        if (!promotion) {
            return res.status(400).json({ error: 'Code promo invalide ou expiré' });
        }

        // Vérifier la limite d'utilisation globale
        if (promotion.usageLimit && promotion.usageCount >= promotion.usageLimit) {
            return res.status(400).json({ error: 'Ce code promo a atteint sa limite d\'utilisation' });
        }

        // Vérifier la limite d'utilisation par utilisateur
        const userUsage = await Order.countDocuments({
            user: req.user.id,
            'promotion.code': code
        });

        if (userUsage >= promotion.userLimit) {
            return res.status(400).json({ error: 'Vous avez déjà utilisé ce code promo' });
        }

        // Vérifier le montant minimum d'achat
        if (cartTotal < promotion.minPurchase) {
            return res.status(400).json({ 
                error: `Le montant minimum d'achat est de ${promotion.minPurchase}€`
            });
        }

        // Calculer la réduction
        let discount = 0;
        if (promotion.type === 'percentage') {
            discount = (cartTotal * promotion.value) / 100;
            if (promotion.maxDiscount) {
                discount = Math.min(discount, promotion.maxDiscount);
            }
        } else {
            discount = promotion.value;
        }

        res.json({
            valid: true,
            discount,
            finalTotal: cartTotal - discount
        });

    } catch (error) {
        logger.error('Verify promo error:', error);
        res.status(500).json({ error: 'Erreur lors de la vérification du code promo' });
    }
});

// Système de notifications
const Notification = mongoose.model('Notification', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users' },
    type: { type: String, enum: ['order', 'promo', 'system'], required: true },
    title: { type: String, required: true },
    message: { type: String, required: true },
    read: { type: Boolean, default: false },
    link: String,
    createdAt: { type: Date, default: Date.now }
});

// Suite du GET /notifications
app.get('/notifications', authenticateToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ 
            user: req.user.id 
        })
        .sort({ createdAt: -1 })
        .limit(20);

        res.json(notifications);
    } catch (error) {
        logger.error('Get notifications error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des notifications' });
    }
});

// Marquer une notification comme lue
app.patch('/notifications/:id/read', authenticateToken, async (req, res) => {
    try {
        const notification = await Notification.findOneAndUpdate(
            { _id: req.params.id, user: req.user.id },
            { read: true },
            { new: true }
        );

        if (!notification) {
            return res.status(404).json({ error: 'Notification non trouvée' });
        }

        res.json(notification);
    } catch (error) {
        logger.error('Mark notification read error:', error);
        res.status(500).json({ error: 'Erreur lors de la mise à jour de la notification' });
    }
});

// Système de wishlist
const Wishlist = mongoose.model('Wishlist', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    products: [{
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        addedAt: { type: Date, default: Date.now }
    }]
});

// Ajouter un produit à la wishlist
app.post('/wishlist/add', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.body;

        let wishlist = await Wishlist.findOne({ user: req.user.id });

        if (!wishlist) {
            wishlist = new Wishlist({
                user: req.user.id,
                products: []
            });
        }

        // Vérifier si le produit est déjà dans la wishlist
        const exists = wishlist.products.some(item => 
            item.product.toString() === productId
        );

        if (!exists) {
            wishlist.products.push({ product: productId });
            await wishlist.save();
        }

        res.json({ success: true, message: 'Produit ajouté à la wishlist' });
    } catch (error) {
        logger.error('Add to wishlist error:', error);
        res.status(500).json({ error: 'Erreur lors de l\'ajout à la wishlist' });
    }
});

// Supprimer un produit de la wishlist
app.delete('/wishlist/remove/:productId', authenticateToken, async (req, res) => {
    try {
        const wishlist = await Wishlist.findOne({ user: req.user.id });

        if (!wishlist) {
            return res.status(404).json({ error: 'Wishlist non trouvée' });
        }

        wishlist.products = wishlist.products.filter(
            item => item.product.toString() !== req.params.productId
        );

        await wishlist.save();
        res.json({ success: true, message: 'Produit retiré de la wishlist' });
    } catch (error) {
        logger.error('Remove from wishlist error:', error);
        res.status(500).json({ error: 'Erreur lors de la suppression de la wishlist' });
    }
});

// Obtenir la wishlist d'un utilisateur
app.get('/wishlist', authenticateToken, async (req, res) => {
    try {
        const wishlist = await Wishlist.findOne({ user: req.user.id })
            .populate('products.product');

        if (!wishlist) {
            return res.json({ products: [] });
        }
    }
});

// Système de commandes
const Order = mongoose.model('Order', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    products: [{
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        quantity: Number,
        price: Number
    }],
    totalAmount: { type: Number, required: true },
    shippingAddress: {
        street: String,
        city: String,
        state: String,
        postalCode: String,
        country: String
    },
    status: {
        type: String,
        enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'],
        default: 'pending'
    },
    paymentStatus: {
        type: String,
        enum: ['pending', 'paid', 'failed'],
        default: 'pending'
    },
    paymentMethod: String,
    trackingNumber: String,
    promotion: {
        code: String,
        discount: Number
    },
    createdAt: { type: Date, default: Date.now }
});

// Créer une nouvelle commande
app.post('/orders', authenticateToken, async (req, res) => {
    try {
        const {
            products,
            shippingAddress,
            paymentMethod,
            promoCode
        } = req.body;

        // Vérifier le stock et calculer le montant total
        let totalAmount = 0;
        const orderProducts = [];

        for (const item of products) {
            const product = await Product.findById(item.productId);
            if (!product || !product.available) {
                return res.status(400).json({ 
                    error: `Le produit ${product.name} n'est plus disponible` 
                });
            }

            orderProducts.push({
                product: product._id,
                quantity: item.quantity,
                price: product.new_price
            });

            totalAmount += product.new_price * item.quantity;
        }

        // Appliquer la promotion si présente
        let appliedPromo = null;
        if (promoCode) {
            const promotion = await Promotion.findOne({ 
                code: promoCode,
                active: true,
                startDate: { $lte: new Date() },
                endDate: { $gte: new Date() }
            });

            if (promotion) {
                const discount = promotion.type === 'percentage' 
                    ? (totalAmount * promotion.value / 100)
                    : promotion.value;

                totalAmount -= discount;
                appliedPromo = {
                    code: promoCode,
                    discount: discount
                };

                // Mettre à jour le compteur d'utilisation de la promotion
                await Promotion.findByIdAndUpdate(
                    promotion._id,
                    { $inc: { usageCount: 1 } }
                );
            }
        }

        // Créer la commande
        const order = new Order({
            user: req.user.id,
            products: orderProducts,
            totalAmount,
            shippingAddress,
            paymentMethod,
            promotion: appliedPromo
        });

        await order.save();

        // Créer une notification pour l'utilisateur
        await new Notification({
            user: req.user.id,
            type: 'order',
            title: 'Nouvelle commande',
            message: `Votre commande #${order._id} a été créée avec succès`,
            link: `/orders/${order._id}`
        }).save();

        res.json({
            success: true,
            orderId: order._id,
            message: 'Commande créée avec succès'
        });

    } catch (error) {
        logger.error('Create order error:', error);
        res.status(500).json({ error: 'Erreur lors de la création de la commande' });
    }
});

// Obtenir les détails d'une commande
app.get('/orders/:orderId', authenticateToken, async (req, res) => {
    try {
        const order = await Order.findOne({
            _id: req.params.orderId,
            user: req.user.id
        }).populate('products.product');

        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        res.json(order);
    } catch (error) {
        logger.error('Get order details error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération de la commande' });
    }
});

// Obtenir l'historique des commandes d'un utilisateur
app.get('/orders', authenticateToken, async (req, res) => {
    try {
        const { status, page = 1, limit = 10 } = req.query;
        const query = { user: req.user.id };

        if (status) {
            query.status = status;
        }

        const orders = await Order.find(query)
            .populate('products.product')
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(Number(limit));

        const total = await Order.countDocuments(query);

        res.json({
            orders,
            totalPages: Math.ceil(total / limit),
            currentPage: page
        });
    } catch (error) {
        logger.error('Get orders history error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des commandes' });
    }
});

// Système de Reviews
const Review = mongoose.model('Review', {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    title: { type: String, required: true },
    comment: { type: String, required: true },
    images: [String],
    verified: { type: Boolean, default: false }, // Pour indiquer si l'achat est vérifié
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Users' }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Ajouter une review
app.post('/products/:productId/reviews', authenticateToken, async (req, res) => {
    try {
        const { rating, title, comment, images } = req.body;
        const productId = req.params.productId;

        // Vérifier si l'utilisateur a déjà laissé une review pour ce produit
        const existingReview = await Review.findOne({
            user: req.user.id,
            product: productId
        });

        if (existingReview) {
            return res.status(400).json({ 
                error: 'Vous avez déjà publié un avis pour ce produit' 
            });
        }

        // Vérifier si l'utilisateur a acheté le produit
        const hasOrdered = await Order.findOne({
            user: req.user.id,
            'products.product': productId,
            status: 'delivered'
        });

        const review = new Review({
            user: req.user.id,
            product: productId,
            rating,
            title,
            comment,
            images,
            verified: !!hasOrdered
        });

        await review.save();

        // Mettre à jour la note moyenne du produit
        const reviews = await Review.find({ product: productId });
        const avgRating = reviews.reduce((acc, rev) => acc + rev.rating, 0) / reviews.length;

        await Product.findByIdAndUpdate(productId, {
            $set: { averageRating: avgRating },
            $inc: { reviewCount: 1 }
        });

        res.json({
            success: true,
            message: 'Avis publié avec succès',
            review
        });

    } catch (error) {
        logger.error('Add review error:', error);
        res.status(500).json({ error: 'Erreur lors de l\'ajout de l\'avis' });
    }
});

// Obtenir les reviews d'un produit
app.get('/products/:productId/reviews', async (req, res) => {
    try {
        const { page = 1, limit = 10, sort = 'recent' } = req.query;
        
        let sortQuery = {};
        switch(sort) {
            case 'recent':
                sortQuery = { createdAt: -1 };
                break;
            case 'rating-high':
                sortQuery = { rating: -1 };
                break;
            case 'rating-low':
                sortQuery = { rating: 1 };
                break;
            case 'liked':
                sortQuery = { 'likes.length': -1 };
                break;
        }

        const reviews = await Review.find({ product: req.params.productId })
            .populate('user', 'name')
            .sort(sortQuery)
            .skip((page - 1) * limit)
            .limit(Number(limit));

        const total = await Review.countDocuments({ product: req.params.productId });

        res.json({
            reviews,
            totalPages: Math.ceil(total / limit),
            currentPage: Number(page)
        });
    } catch (error) {
        logger.error('Get reviews error:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des avis' });
    }
});

// Système de recherche avancée
app.get('/search', async (req, res) => {
    try {
        const {
            query,
            category,
            minPrice,
            maxPrice,
            sort = 'relevance',
            page = 1,
            limit = 12
        } = req.query;

        // Construire la requête de recherche
        let searchQuery = {};

        if (query) {
            searchQuery.$or = [
                { name: { $regex: query, $options: 'i' } },
                { category: { $regex: query, $options: 'i' } }
            ];
        }

        if (category) {
            searchQuery.category = category;
        }

        if (minPrice || maxPrice) {
            searchQuery.new_price = {};
            if (minPrice) searchQuery.new_price.$gte = Number(minPrice);
            if (maxPrice) searchQuery.new_price.$lte = Number(maxPrice);
        }

        // Gérer le tri
        let sortQuery = {};
        switch(sort) {
            case 'price-asc':
                sortQuery = { new_price: 1 };
                break;
            case 'price-desc':
                sortQuery = { new_price: -1 };
                break;
            case 'newest':
                sortQuery = { date: -1 };
                break;
            case 'popular':
                sortQuery = { reviewCount: -1 };
                break;
            case 'rating':
                sortQuery = { averageRating: -1 };
                break;
        }

        const products = await Product.find(searchQuery)
            .sort(sortQuery)
            .skip((page - 1) * limit)
            .limit(Number(limit));

        const total = await Product.countDocuments(searchQuery);
        priceRanges: {
            min: await Product.find().sort({ new_price: 1 }).limit(1).then(p => p[0]?.new_price || 0),
            max: await Product.find().sort({ new_price: -1 }).limit(1).then(p => p[0]?.new_price || 0)
        },
        totalProducts: total,
        availableFilters: {
            sortOptions: [
                { value: 'relevance', label: 'Pertinence' },
                { value: 'price-asc', label: 'Prix croissant' },
                { value: 'price-desc', label: 'Prix décroissant' },
                { value: 'newest', label: 'Plus récents' },
                { value: 'popular', label: 'Plus populaires' },
                { value: 'rating', label: 'Mieux notés' }
            ]
        }
    };

    res.json({
        products,
        facets,
        pagination: {
            currentPage: Number(page),
            totalPages: Math.ceil(total / limit),
            totalItems: total
        }
    });
} catch (error) {
    logger.error('Search error:', error);
    res.status(500).json({ error: 'Erreur lors de la recherche' });
}
});

// Système de recommandations
app.get('/recommendations', authenticateToken, async (req, res) => {
try {
    const { type = 'personal' } = req.query;
    let recommendations = [];

    switch(type) {
        case 'personal':
            // Recommandations basées sur l'historique d'achat
            const userOrders = await Order.find({ user: req.user.id })
                .populate('products.product');
            
            const purchasedCategories = new Set();
            userOrders.forEach(order => {
                order.products.forEach(item => {
                    if (item.product) {
                        purchasedCategories.add(item.product.category);
                    }
                });
            });

            recommendations = await Product.find({
                category: { $in: Array.from(purchasedCategories) },
                available: true
            })
            .sort({ averageRating: -1 })
            .limit(10);
            break;

        case 'trending':
            // Produits les plus vendus récemment
            recommendations = await Order.aggregate([
                { $unwind: '$products' },
                { $group: {
                    _id: '$products.product',
                    totalSold: { $sum: '$products.quantity' }
                }},
                { $sort: { totalSold: -1 } },
                { $limit: 10 }
            ]).then(async (results) => {
                const productIds = results.map(r => r._id);
                return Product.find({ 
                    _id: { $in: productIds },
                    available: true
                });
            });
            break;

        case 'similar':
            const { productId } = req.query;
            if (!productId) {
                return res.status(400).json({ error: 'ProductId requis pour les recommandations similaires' });
            }

            const baseProduct = await Product.findById(productId);
            if (!baseProduct) {
                return res.status(404).json({ error: 'Produit non trouvé' });
            }

            recommendations = await Product.find({
                category: baseProduct.category,
                _id: { $ne: baseProduct._id },
                available: true
            })
            .sort({ averageRating: -1 })
            .limit(10);
            break;
    }

    res.json({
        success: true,
        recommendations
    });

} catch (error) {
    logger.error('Recommendations error:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des recommandations' });
}
});

// Gestion des catégories
const Category = mongoose.model('Category', {
name: { type: String, required: true, unique: true },
slug: { type: String, required: true, unique: true },
description: String,
image: String,
parent: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
isActive: { type: Boolean, default: true },
createdAt: { type: Date, default: Date.now },
updatedAt: { type: Date, default: Date.now }
});

// Créer une nouvelle catégorie
app.post('/categories', async (req, res) => {
try {
    const { name, description, parentId, image } = req.body;
    const slug = name.toLowerCase().replace(/\s+/g, '-');

    const category = new Category({
        name,
        slug,
        description,
        image,
        parent: parentId
    });

    await category.save();
    res.status(201).json({
        success: true,
        category
    });
} catch (error) {
    logger.error('Create category error:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la catégorie' });
}
});

// Obtenir l'arborescence des catégories
app.get('/categories/tree', async (req, res) => {
try {
    const categories = await Category.find({ isActive: true })
        .populate('parent');

    const buildTree = (categories, parentId = null) => {
        return categories
            .filter(category => 
                parentId === null ? !category.parent : category.parent?._id.toString() === parentId.toString()
            )
            .map(category => ({
                ...category.toObject(),
                children: buildTree(categories, category._id)
            }));
    };

    const categoryTree = buildTree(categories);
    res.json(categoryTree);
} catch (error) {
    logger.error('Get category tree error:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des catégories' });
}
});

// Statistiques et analytics
app.get('/analytics', async (req, res) => {
try {
    const { startDate, endDate } = req.query;
    const dateFilter = {};
    
    if (startDate && endDate) {
        dateFilter.createdAt = {
            $gte: new Date(startDate),
            $lte: new Date(endDate)
        };
    }

    // Statistiques des ventes
    const salesStats = await Order.aggregate([
        { $match: dateFilter },
        { $group: {
            _id: null,
            totalSales: { $sum: '$total' },
            orderCount: { $sum: 1 },
            averageOrderValue: { $avg: '$total' }
        }}
    ]);

    // Produits les plus vendus
    const topProducts = await Order.aggregate([
        { $match: dateFilter },
        { $unwind: '$products' },
        { $group: {
            _id: '$products.product',
            totalQuantity: { $sum: '$products.quantity' },
            totalRevenue: { $sum: { $multiply: ['$products.price', '$products.quantity'] } }
        }},
        { $sort: { totalQuantity: -1 } },
        { $limit: 5 },
        { $lookup: {
            from: 'products',
            localField: '_id',
            foreignField: '_id',
            as: 'productDetails'
        }},
        { $unwind: '$productDetails' }
    ]);

    // Statistiques des utilisateurs
    const userStats = await Users.aggregate([
        { $match: dateFilter },
        { $group: {
            _id: null,
            totalUsers: { $sum: 1 },
            newUsers: {
                $sum: {
                    $cond: [
                        { $gte: ['$date', new Date(startDate)] },
                        1,
                        0
                    ]
                }
            }
        }}
    ]);

    // Statistiques par catégorie
    const categoryStats = await Order.aggregate([
        { $match: dateFilter },
        { $unwind: '$products' },
        { $lookup: {
            from: 'products',
            localField: 'products.product',
            foreignField: '_id',
            as: 'productDetails'
        }},
        { $unwind: '$productDetails' },
        { $group: {
            _id: '$productDetails.category',
            totalSales: { $sum: { $multiply: ['$products.price', '$products.quantity'] } },
            itemsSold: { $sum: '$products.quantity' }
        }},
        { $sort: { totalSales: -1 } }
    ]);

    res.json({
        salesStats: salesStats[0],
        topProducts,
        userStats: userStats[0],
        categoryStats
    });
} catch (error) {
    logger.error('Analytics error:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des statistiques' });
}
});

// Schéma pour les commandes
const OrderSchema = new mongoose.Schema({
user: { type: mongoose.Schema.Types.ObjectId, ref: 'Users', required: true },
products: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    quantity: { type: Number, required: true },
    price: { type: Number, required: true }
}],
total: { type: Number, required: true },
status: {
    type: String,
    enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
},
shippingAddress: {
    street: String,
    city: String,
    state: String,
    postalCode: String,
    country: String
},
paymentMethod: String,
paymentStatus: {
    type: String,
    enum: ['pending', 'completed', 'failed'],
    default: 'pending'
},
trackingNumber: String,
createdAt: { type: Date, default: Date.now },
updatedAt: { type: Date, default: Date.now }
});

const Order = mongoose.model('Order', OrderSchema);

// Créer une nouvelle commande
app.post('/orders', authenticateToken, async (req, res) => {
try {
    const { products, shippingAddress, paymentMethod } = req.body;

    // Vérifier la disponibilité des produits et calculer le total
    let total = 0;
    const orderProducts = [];
    
    for (const item of products) {
        const product = await Product.findById(item.productId);
        if (!product || !product.available) {
            return res.status(400).json({
                error: `Le produit ${item.productId} n'est pas disponible`
            });
        }

        orderProducts.push({
            product: product._id,
            quantity: item.quantity,
            price: product.new_price
        });

        total += product.new_price * item.quantity;
    }

    const order = new Order({
        user: req.user.id,
        products: orderProducts,
        total,
        shippingAddress,
        paymentMethod
    });

    await order.save();

    // Mettre à jour le stock des produits