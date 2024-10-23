const port = 4000;
const express = require("express");
const session = require('express-session');
const app = express();
const mongoose = require("mongoose");
const MongoStore = require('connect-mongo');
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require('fs');
const path = require("path");
const cors = require("cors");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

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

const router = express.Router()

module.exports = router

// Database Connexion with MongoDB
mongoose.connect("mongodb+srv://Farouk:Naruto12@cluster0.jjsmv.mongodb.net/e-commerce")

// API Creation

app.get("/",(req,res)=>{
    res.send("Express App is Running")
})

// Image Storage Engine

const storage = multer.diskStorage({
    destination: './upload/images',
    filename: (req, file, cb) =>{
        return cb(null,`${file.fieldname}_${Date.now()}${path.extname(file.originalname)}`)
    }
})

const upload = multer({storage:storage})

// Creating Upload Endpoint for images

app.use('/images',express.static('upload/images'))

app.post("/upload",upload.single('product'),(req,res)=>{
    res.json({
        success:1,
        image_url:`http://localhost:${port}/images/${req.file.filename}`
    })
})

// Schema for Creating Products

const Product = mongoose.model("Product",{
    id:{
        type:Number,
        required: true,
    },
    name:{
        type:String,
        required: true,
    },
    image:{
        type:String,
        required: true,
    },
    category:{
        type:String,
        required: true,
    },
    new_price:{
        type:Number,
        required: true,
    },
    old_price:{
        type:Number,
        required: true,
    },
    date:{
        type:Date,
        default:Date.now,
    },
    available:{
        type:Boolean,
        default:true,
    },
})

app.post('/addproduct',async(req,res)=>{
    let products = await Product.find({});
    let id;
    if(products.lenght>0)
    {
        let last_product_array = products.slice(-1);
        let last_product = last_product_array[0];
        id = last_product.id+1;
    }
    else{
        id=1;
    }
    const product = new Product({
        id: id,
        name: req.body.name,
        image: req.body.image,
        category: req.body.category,
        new_price: req.body.new_price,
        old_price: req.body.old_price,
    });
    console.log(product);
    await product.save();
    console.log("Saved");
    res.json({
        success: true,
        name: req.body.name,
    })
})

// Creating API For deleting Products

app.post('/removeproduct',async(req,res)=>{
    await Product.findOneAndDelete({id:req.body.id});
    console.log("Removed");
    res.json({
        success: true,
        name: req.body.name,
    })
})

// Creating API for getting all products
app.get('/allproducts',async(req,res)=>{
    let products = await Product.find({});
    console.log("All Products Fetched");
    res.send(products);
})

// Creating API for update all products
app.patch('/updateproduct/:id', async (req, res) => {
    try {
      const updateProduct = await Product.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
      });
      res.status(200).json({
        status: "succes",
        data: {
          product: updateProduct
        }
      })
    } catch (error) {
      res.status(404).json({
        status: "fail",
        message: error.message
      })
    }
  })

// Shema creation for User model

const Users = mongoose.model('Users',{
    name:{
        type:String,
    },
    email:{
        type:String,
        unique:true,
    },
    password:{
        type:String,
    },
    cartData:{
        type:Object,
    },
    date:{
        type:Date,
        default:Date.now,
    }
})

// Creating Endpoint for registering the user
app.post('/signup',async(req,res)=>{

    let check = await Users.findOne({email:req.body.email});
    if (check) {
        return res.status(400).json({success:false,errors:"existing user found with same email address"})
    }
    let cart = {};
    for (let i = 0; i < 300; i++) {
        cart[i]=0;
    }
    const user = new Users({
        name:req.body.username,
        email:req.body.email,
        password:req.body.password,
        cartData:cart,
    })

    await user.save();

    const data = {
        user:{
            id:user.id
        }
    }

    const token = jwt.sign(data,'secret_ecom');
    res.json({success:true,token})

})

// API endpoint to retrieve the username
app.get('/users:_id', async (req, res) => {
    const user = await Users.findOne({ email: req.user.email });
    if (!user) {
      return res.status(404).json({ success: false, errors: 'User  not found' });
    }
    console.log('Username:', user.name); // Add this line
    res.json({ name: user.name });
  });

// Creating endpoint for user login
app.post('/login',async(req,res)=>{
    let user = await Users.findOne({email:req.body.email});
    if (user) {
        const passCompare = req.body.password === user.password;
        if (passCompare) {
            const data = {
                user:{
                    id:user.id
                }
            }
            const token = jwt.sign(data,'secret_ecom')
            res.json({success:true,token})
        }
        else{
            res.json({success:false,errors:"Wrong Password"});
        }
    }
    else{
        res.json({succes:false,errors:"Wrong Email Id"})
    }
})

// Creating API for getting all users
app.get('/allusers',async(req,res)=>{
    let users = await Users.find({});
    console.log("All Users Fetched");
    res.send(users);
})

// Creating API For deleting Users
app.post('/removeuser',async(req,res)=>{
    await Users.findOneAndDelete({id:Users._id});
    console.log("Removed");
    res.json({
        success: true,
        id: Users._id,
    })
})

// Creating API For Updating Users
app.patch('/updateuser:_id', async (req, res) => {
    try {
      const userId = req.body.id; // Récupérer l'ID de l'utilisateur
      const updateUser = await Users.findByIdAndUpdate(userId, {
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
      }, {
        new: true,
        runValidators: true
      });
      console.log("Updated");
      res.status(200).json({
        status: "success",
        data: {
          user: updateUser
        }
      })
    } catch (error) {
      console.error(error);
      res.status(404).json({ status: "fail", message: error.message });
    }
  })

// API for frontend user update
app.put("/profileupdate", async (req, res) => {
    try {
      const { username, email, password, newPassword, confirmPassword } = req.body;
      const user = await Users.findById(req.user._id);
  
      if (!user) {
        return res.status(404).json({ message: "Utilisateur non trouvé" });
      }
  
      if (password !== user.password) {
        return res.status(401).json({ message: "Mot de passe incorrect" });
      }
  
      if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: "Les mots de passe ne correspondent pas" });
      }
  
      user.username = username;
      user.email = email;
      user.password = newPassword;
  
      await user.save();
  
      res.json({ success: true, message: "Profil mis à jour avec succès" });
    } catch (error) {
      res.status(500).json({ message: "Erreur serveur" });
    }
  });

// Creating endpoint for newcollection data
app.get('/newcollections', async(req,res)=>{
    let products = await Product.find({});
    let newcollection = products.slice(1).slice(-8);
    console.log("NewCollection Fetched");
    res.send(newcollection);
})

// Creating endpoint for popular in one piece section
app.get('/popularinonepiece', async(req,res)=>{
    let products = await Product.find({category:"onepiece"});
    let popular_in_onepiece = products.slice(0,4);
    console.log("Popular in onepiece fetched");
    res.send(popular_in_onepiece);
})

// Creating middleware to fetch user
const fetchUser = async (req,res,next)=>{
    const token = req.header('auth-token');
    if (!token) {
        res.status(401).send({errors:"Please authenticate using valide token"})
    }
    else{
        try {
            const data = jwt.verify(token,'secret_ecom');
            req.user = data.user;
            next();
        } catch (error) {
            res.status(401).send({errors:"Please authenticate using a valide token"})
        }
    }
}

// Creating endpoint for ading products in cartdata
app.post('/addtocart',fetchUser,async(req,res)=>{
    let userData = await Users.findOne({_id:req.user.id});
    userData.cartData[req.body.itemId] += 1;
    await Users.findOneAndUpdate({_id:req.user.id},{cartData:userData.cartData});
    res.send("Added")
})

// Creating endpoint to remove product from cartData
app.post('/removefromcart',fetchUser,async(req,res)=>{
    let userData = await Users.findOne({_id:req.user.id});
    if(userData.cartData[req.body.itemId]>0)
    userData.cartData[req.body.itemId] -= 1;
    await Users.findOneAndUpdate({_id:req.user.id},{cartData:userData.cartData});
    res.send("Removed")
})

// Creating endpoint to get cartdata
app.post('/getcart',fetchUser,async(req,res)=>{
    let userData = await Users.findOne({_id:req.user.id});
    res.json(userData.cartData);
})

app.listen(port,(error)=>{
    if(!error){
        console.log("Server Running on Port "+port)
    }
    else{
        console.log("Error : "+error)
    }
})