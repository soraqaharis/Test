const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser')
const app = express();
app.use(cookieParser())
app.use(cors())
require('dotenv').config()
const User = require('./user.models')
app.use(express.json());
const port = process.env.PORT;

mongoose.connect('mongodb://localhost:27017/test', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(()=>{
    console.log('MongoDB Connect')
}).catch(err=> console.log('error', err))


app.get('/', (req, res)=>{
    res.send('Hello from server')
});

app.post('/register', async (req, res)=>{
    const {name, email, phone, password} = req.body;
    if(!name || !email || !phone || !password){
        return res.status(422).json({message: 'Please all fill'})
    }
    try {
        const existUser = await User.findOne({email})
        if(existUser){
            return res.status(422).json({message: 'User Already exist'})
        }
         const hashPassword = await bcrypt.hash(password, 10)
        const user = new User({name, email, phone, password: hashPassword})
        await user.save()
        res.status(201).json({message: 'user register successfully'})
    } catch (error) {
        res.status(500).json({message: 'something error'})
    }
});

app.post('/loginn', async (req, res)=>{
    const {email, password} = req.body;
    if(!email || !password){
        return res.status(422).json({message: 'fill al input'})
    }
    
    const user = await User.findOne({email});
    if(!user){
       return res.status(422).json({message: 'User not register'})
    }
    const matchP = await bcrypt.compare(password, user.password);
    if(!matchP){
       return res.status(422).json({message:'email or password are invalid'})
    }
    

    const token = await jwt.sign({_id: user._id}, process.env.KEY)
    res.cookie('token', token, {
        maxAge: 3600000,
        httpOnly: true
    })
    res.status(200).json({ message: 'Login successful' });

})

app.get('/user', async (req, res)=>{
    const user = await User.find()
    res.json(user)
})

app.get('/verifyuser', async (req, res) => {
    const token = req.cookies.token;
    if(!token){
        return res.status(422).json({message:'not found'})
       }
    try {
        const decodes = await jwt.verify(token, process.env.KEY)
        const user = await User.findById(decodes._id)
    if(!user){
     return res.status(422).json({message:'no verify'})
    }
    res.json({user})
    } catch (error) {
        res.status(500).json({message:'token error'})
    }

})

app.get('/logout', (req, res)=>{
    res.clearCookie('token');
    res.status(200).json({message: 'logout'})
})

app.listen(port, ()=>{
    console.log(`server is listening at port no ${port}`)
})