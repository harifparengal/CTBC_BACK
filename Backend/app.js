require('dotenv').config();
const express = require("express");
const app = express();
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { validationResult, check } = require('express-validator');
const AdminUser = require("./models/AdminUser");
const Event = require("./models/Event");
const Project = require("./models/Project");
const Blog = require("./models/Blog");
const mongoose = require("mongoose");
const crypto = require('crypto');
const axios = require('axios');
const corsOptions = require("./config/corsOptions");
const { rateLimit } = require('express-rate-limit')
const port = 8080;

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 50, // limit each IP to 50 requests per 1m
})


// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json({limit:"10mb"}));
app.use(helmet());
app.use(cors(corsOptions));
app.use(limiter);

// routes
app.get("/", (req, res) => {
  res.send("Welcome to ctbc");
});

// database connection

async function main() {
  try {
    await mongoose.connect(process.env.DB_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("Connected to the database ctbc");
    app.listen(port, () => {
      console.log("Listening to Port Number " + port);
    });
  } catch (error) {
    console.error("Error connecting to the database:", error);
  }
}

main();


app.post("/api/v1/user", async (req, res) => {
  const { email, user } = req.body;
  console.log(email, user);
  if (!email || !user) {
    return res.status(400).json({ error: "All fields are required" });
  }
  try {
    const newUser = await User.create({ email, user });
    console.log("New user created:", newUser);
    return res.status(200).json({ user: newUser });
  } catch (error) {
    console.error("Error creating user:", error);
    return res.status(400).json({ error: error.message });
  }
});

// Authentication Middleware
const verifyJwt = (req, res, next) => {
  const token = req.headers.authorization || null;
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// Routes
app.post('/add-moderator', [check('email').isEmail(), check('password').isLength({ min: 6 }),], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;
  const saltRounds = 10;

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const user = {
    email,
    password: hashedPassword,
  };

  try {
    await User.save(user);
    res.status(201).json({ message: 'User registered' });
  } catch (error) {
    res.status(500).json({ message: 'Registration failed' });
  }
}
);

app.post('/loginA', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await AdminUser.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.status(200).send({ admin: true, "token": token });
  } catch (error) {
    res.status(500).json({ message: 'Login failed' });
  }
});

app.post('/validateToken', verifyJwt, async (req, res) => {

  try {
    const user = await AdminUser.findOne({ _id: req.user._id });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const data = { "valid": true };
    res.send(data);
  }
  catch (error) {
    res.status(500).json({ message: 'Validation failed' });
  }
});

app.get('/events', async (req, res) => {
  try {
    const datas = await Event.find({});
    const events = datas.map(data => { return { ...data._doc, img: Buffer.from(data._doc.img).toString('base64') }})
    res.send(events);
  }
  catch (error) {
    res.status(500).json({ message: 'request failed' });
  }
})

app.post('/add-event', verifyJwt, async (req, res) => {
  try {
    const { description, amount, img } = req.body;
    const imageBuffer = Buffer.from(img.split(',')[1],'base64');

    const event = new Event({
      description,
      amount,
      img: imageBuffer
    });
    await event.save();
    res.status(200).json({ message: 'Event added successfully.' });
  }
  catch (error) {
    res.status(500).json({ message: 'request failed' });
  }
})

app.delete('/delete-event/:id', verifyJwt, async (req, res) => {
  try {
    await Event.deleteOne({ _id: req.params.id });
    res.status(200).send({ message: "Item successfully deleted", id: req.params.id });
  }
  catch (error) {
    res.status(500).json({ message: 'request failed' });
  }
})

app.get('/projects', async (req, res) => {
  try {
    const datas = await Project.find({});
    const projects = datas.map(data => { return { ...data._doc, img: Buffer.from(data._doc.img).toString('base64') } })
    res.send(projects);
  }
  catch (error) {
    res.status(500).json({ message: 'request failed' });
  }
})

app.post('/add-project', verifyJwt, async (req, res) => {
  try {
    const { description, tag, img,name } = req.body;
    const imageBuffer = Buffer.from(img.split(',')[1], 'base64');

    const project = new Project({
      description,
      tag,
      img: imageBuffer,
      name
    });
    await project.save();
    res.status(200).json({ message: 'Project added successfully.' });
  }
  catch (error) {
    res.status(500).json({ message: 'request failed' });
  }
})

app.delete('/delete-project/:id', verifyJwt, async (req, res) => {
  try {
    await Project.deleteOne({ _id: req.params.id });
    res.status(200).send({ message: "Item successfully deleted", id: req.params.id });
  }
  catch (error) {
    res.status(500).json({ message: 'request failed' });
  }
})

app.get('/blogs', async (req, res) => {
  try {
    const datas = await Blog.find({});
    const blogs = datas.map(data => { return { ...data._doc, img: Buffer.from(data._doc.img).toString('base64') } });
    res.send(blogs);
  }
  catch (error) {
    res.status(500).json({ message: 'request failed' });
  }
})

app.post('/add-blog', verifyJwt, async (req, res) => {
  try {
    const { description, img, name } = req.body;
    const imageBuffer = Buffer.from(img.split(',')[1], 'base64');

    const blog = new Blog({
      description,
      img: imageBuffer,
      name
    });
    await blog.save();
    res.status(200).json({ message: 'Project added successfully.' });
  }
  catch (error) {
    res.status(500).json({ message: 'request failed' });
  }
})

app.delete('/delete-blog/:id', verifyJwt, async (req, res) => {
  try {
    await Blog.deleteOne({ _id: req.params.id });
    res.status(200).send({ message: "Item successfully deleted", id: req.params.id });
  }
  catch (error) {
    res.status(500).json({ message: 'request failed' });
  }
})



app.post('/pay', async (req, res) => {
  try {
    const event = await Event.findById(req.body._id, "amount");
    const amount = event?.amount;
    
    const payload = {
      "merchantId": process.env.MerchantId,
      "merchantTransactionId": req.body.date, //in miliseconds
      "merchantUserId": req.body.name,
      "amount": amount * 100,
      "redirectUrl": `${process.env.CTBC_SITE_URL}/events`,
      "redirectMode": "POST",
      "callbackUrl": `${process.env.CTBC_SERVER_URL}/pay-status`,
      "mobileNumber": req.body.phone,
      "paymentInstrument": {
        "type": "PAY_PAGE"
      }
    };
    const payload1 = {
      "merchantId": "PGTESTPAYUAT",
      "merchantTransactionId": "MT7850590068188104",
      "merchantUserId": "MUID123",
      "amount": 10000,
      "redirectUrl": "http://localhost:5173",
      "redirectMode": "POST",
      "callbackUrl": "http://localhost:8080/pay-status",
      "mobileNumber": "9999999999",
      "paymentInstrument": {
        "type": "PAY_PAGE"
      }
    }

    const payloadJson = JSON.stringify(payload);
    const requestString = Buffer.from(payloadJson).toString('base64');

    const hashString = requestString + '/pg/v1/pay' + process.env.PayKey;
    const hash = crypto.createHash('sha256').update(hashString).digest('hex');
    const checksumHeader = hash + '###' + process.env.PayKeyIndex;
    const options = {
      method: 'POST',
      url: 'https://api.phonepe.com/apis/hermes/pg/v1/pay',
      headers: {
        accept: 'application/json',
        'Content-Type': 'application/json',
        'X-VERIFY': checksumHeader
      },
      data: { request: requestString }
    };
    const result = await axios.request(options);
    res.send(result.data);
  }
  catch (error) {
    res.status(500).json({ message: error.message });
  }
})

app.post('/pay-status', async (req, res) => {
  console.log(req.body)
res.send(req.body)
})