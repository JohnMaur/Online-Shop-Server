require('dotenv').config();
const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const bodyParser = require('body-parser');
const cors = require("cors");
const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
const bcrypt = require('bcryptjs');
const { ObjectId } = require('mongodb');
const crypto = require("crypto");
const nodemailer = require('nodemailer');

const app = express();
app.use(cors({ origin: "*" }));
app.use(bodyParser.json()); // Parse JSON request bodies

// MongoDB URI and client setup
const uri = process.env.MONGO_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Connect to MongoDB
let db;
client.connect().then(() => {
  console.log('Connected to MongoDB Atlas!');
  db = client.db('user_account'); // Select database
});

// Secret for JWT
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

// Helper function to generate JWT
const generateToken = (user) => {
  return jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '7d' }); // Token valid for 7 days
};

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};
// -------------------------------------- USERS ----------------------------------------
// --------------------------USER ACCOUNT--------------------------
// API to create a user account
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }

    if (username.length > 25 || password.length > 25) {
      return res.status(400).json({ message: 'Username and password must be 25 characters or fewer.' });
    }

    // Check if the user already exists
    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: 'Username already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user
    await db.collection('users').insertOne({ username, password: hashedPassword });
    return res.status(201).json({ message: 'Account created successfully.' });
  } catch (err) {
    console.error('Error creating account:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// app.post('/api/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;

//     if (!username || !password) {
//       return res.status(400).json({ message: 'Username and password are required.' });
//     }

//     const user = await db.collection('users').findOne({ username });
//     if (!user) {
//       return res.status(404).json({ message: 'User not found.' });
//     }

//     const isPasswordValid = await bcrypt.compare(password, user.password);
//     if (!isPasswordValid) {
//       return res.status(401).json({ message: 'Invalid credentials.' });
//     }

//     const token = generateToken(user);

//     // Check if user has account info
//     const userInfo = await db.collection('account_info').findOne({ username });

//     return res.status(200).json({
//       message: 'Login successful',
//       token,
//       needsUpdate: !userInfo, // If no account info exists, prompt update
//     });
//   } catch (err) {
//     console.error('Error during login:', err);
//     return res.status(500).json({ message: 'Internal server error.' });
//   }
// });

// app.post('/api/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;

//     if (!username || !password) {
//       return res.status(400).json({ message: 'Username and password are required.' });
//     }

//     const user = await db.collection('users').findOne({ username });
//     if (!user) {
//       return res.status(404).json({ message: 'User not found.' });
//     }

//     let isPasswordValid = false;

//     // Check if the stored password is a bcrypt hash (typically starts with $2a$, $2b$, or $2y$)
//     if (user.password.startsWith('$2')) {
//       isPasswordValid = await bcrypt.compare(password, user.password);
//     } else {
//       isPasswordValid = password === user.password;
//     }

//     if (!isPasswordValid) {
//       return res.status(401).json({ message: 'Invalid credentials.' });
//     }

//     const token = generateToken(user);

//     // Check if user has account info
//     const userInfo = await db.collection('account_info').findOne({ username });

//     return res.status(200).json({
//       message: 'Login successful',
//       token,
//       needsUpdate: !userInfo,
//     });
//   } catch (err) {
//     console.error('Error during login:', err);
//     return res.status(500).json({ message: 'Internal server error.' });
//   }
// });

// With active user ID
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }

    const user = await db.collection('users').findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    let isPasswordValid = false;

    if (user.password.startsWith('$2')) {
      isPasswordValid = await bcrypt.compare(password, user.password);
    } else {
      isPasswordValid = password === user.password;
    }

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Check if user is already logged in on another device
    if (user.activeUserID) {
      return res.status(409).json({ message: 'User already logged in on another device.' });
    }

    const token = generateToken(user);
    const activeUserID = crypto.randomBytes(16).toString('hex');

    await db.collection('users').updateOne({ username }, { $set: { activeUserID } });

    const userInfo = await db.collection('account_info').findOne({ username });

    return res.status(200).json({
      message: 'Login successful',
      token,
      activeUserID,
      needsUpdate: !userInfo,
    });
  } catch (err) {
    console.error('Error during login:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});


app.post('/api/logout', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) {
      return res.status(400).json({ message: 'Username is required for logout.' });
    }

    await db.collection('users').updateOne(
      { username },
      { $unset: { activeUserID: "" } }
    );

    return res.status(200).json({ message: 'Logout successful, activeUserID removed.' });
  } catch (err) {
    console.error('Error during logout:', err);
    return res.status(500).json({ message: 'Internal server error during logout.' });
  }
});



// User change password
// Change password
// app.post("/api/userChange-password", async (req, res) => {
//   try {
//     const { username, oldPassword, newPassword } = req.body;

//     if (!username || !oldPassword || !newPassword) {
//       return res.status(400).json({ message: "All fields are required." });
//     }

//     const user = await db.collection("users").findOne({ username });
//     if (!user) {
//       return res.status(404).json({ message: "User not found." });
//     }

//     const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
//     if (!isPasswordValid) {
//       return res.status(401).json({ message: "Incorrect old password." });
//     }

//     const hashedNewPassword = await bcrypt.hash(newPassword, 10);
//     await db.collection("users").updateOne({ username }, { $set: { password: hashedNewPassword } });

//     res.status(200).json({ message: "Password changed successfully." });
//   } catch (err) {
//     console.error("Error changing password:", err);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });
app.post("/api/userChange-password", async (req, res) => {
  try {
    const { username, oldPassword, newPassword } = req.body;

    if (!username || !oldPassword || !newPassword) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const user = await db.collection("users").findOne({ username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    let isPasswordValid = false;

    // Detect if the password is hashed (bcrypt hashes start with $2)
    if (user.password.startsWith('$2')) {
      isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    } else {
      isPasswordValid = oldPassword === user.password;
    }

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Incorrect old password." });
    }

    // Always hash the new password before saving
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await db.collection("users").updateOne({ username }, { $set: { password: hashedNewPassword } });

    res.status(200).json({ message: "Password changed successfully." });
  } catch (err) {
    console.error("Error changing password:", err);
    res.status(500).json({ message: "Internal server error." });
  }
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
app.post('/api/forgot-password', async (req, res) => {
  const { username } = req.body;

  try {
    const userInfo = await db.collection('account_info').findOne({ username });

    if (!userInfo || !userInfo.gmail) {
      console.log("No email found for user:", username);
      return res.status(404).json({ message: 'Email not found for user' });
    }

    const otp = generateOTP();

    // Save OTP to `users` collection
    const userUpdate = await db.collection('users').updateOne(
      { username },
      { $set: { otp } }
    );

    if (userUpdate.matchedCount === 0) {
      console.log("User not found in users collection:", username);
      return res.status(404).json({ message: 'User not found' });
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: "onlineshopmacky@gmail.com",
        pass: "yiqg icdd jjzh pdvg", // This should be a Gmail App Password (not regular password)
      },
      tls: {
        rejectUnauthorized: false, // Add this line to allow self-signed certificates
      },
    });


    await transporter.sendMail({
      from: "bennydictuz3@gmail.com",
      to: userInfo.gmail,
      // to: "onlineshopmacky@gmail.com",
      subject: 'Password Reset OTP',
      text: `Your OTP is: ${otp}`,
    });

    return res.status(200).json({ message: 'OTP sent successfully' });

  } catch (err) {
    console.error("Error in /api/forgot-password:", err);
    return res.status(500).json({ message: 'Error sending OTP' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { username, otp, newPassword } = req.body;

  try {
    const user = await db.collection('users').findOne({ username });

    if (!user || user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.collection('users').updateOne(
      { username },
      { $set: { password: hashedPassword }, $unset: { otp: "" } }
    );

    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

app.post('/api/send-force-logout-otp', async (req, res) => {
  const { username } = req.body;

  try {
    const userInfo = await db.collection('account_info').findOne({ username });
    if (!userInfo?.gmail) return res.status(404).json({ message: 'Email not found for user' });

    const otp = generateOTP();
    await db.collection('users').updateOne({ username }, { $set: { otp } });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: "onlineshopmacky@gmail.com",
        pass: "yiqg icdd jjzh pdvg", // This should be a Gmail App Password (not regular password)
      },
      tls: {
        rejectUnauthorized: false, // Add this line to allow self-signed certificates
      },
    });

    await transporter.sendMail({
      from: "bennydictuz3@gmail.com",
      to: userInfo.gmail,
      subject: 'Login Verification Code for This Device',
      text: `Your OTP to continue login on this device is: ${otp}`,
    });

    return res.status(200).json({ message: 'OTP sent successfully' });
  } catch (err) {
    console.error("Error sending OTP:", err);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

app.post('/api/verify-force-logout-otp', async (req, res) => {
  const { username, otp } = req.body;

  try {
    const user = await db.collection('users').findOne({ username });

    if (!user || user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    await db.collection('users').updateOne(
      { username },
      { $unset: { activeUserID: "", otp: "" } }
    );

    res.status(200).json({ message: 'User forcibly logged out' });
  } catch (err) {
    console.error('Error verifying OTP:', err);
    res.status(500).json({ message: 'Error verifying OTP' });
  }
});


  
// --------------------------END OF USER ACCOUNT--------------------------

// ---------------------USER INFO--------------------------------
// Users account info
app.get('/api/account-info/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const userInfo = await db.collection('account_info').findOne({ username });

    if (!userInfo) {
      return res.status(404).json({ message: "User account info not found." });
    }

    res.status(200).json(userInfo);
  } catch (err) {
    console.error('Error fetching account info:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// app.post('/api/update-account', async (req, res) => {
//   try {
//     const { username, region, houseStreet, recipientName, phoneNumber } = req.body;

//     if (!username) {
//       return res.status(400).json({ message: 'Username is required.' });
//     }

//     const existingInfo = await db.collection('account_info').findOne({ username });

//     if (existingInfo) {
//       // Update existing info
//       await db.collection('account_info').updateOne(
//         { username },
//         { $set: { region, houseStreet, recipientName, phoneNumber } }
//       );
//     } else {
//       // Insert new info
//       await db.collection('account_info').insertOne({ username, region, houseStreet, recipientName, phoneNumber });
//     }

//     return res.status(200).json({ message: 'Account info saved successfully.' });
//   } catch (err) {
//     console.error('Error updating account info:', err);
//     return res.status(500).json({ message: 'Internal server error.' });
//   }
// });

app.post('/api/update-account', async (req, res) => {
  try {
    const { username, region, houseStreet, recipientName, phoneNumber, gmail } = req.body;

    if (!username) {
      return res.status(400).json({ message: 'Username is required.' });
    }

    const existingInfo = await db.collection('account_info').findOne({ username });

    if (existingInfo) {
      // Update existing info
      await db.collection('account_info').updateOne(
        { username },
        { $set: { region, houseStreet, recipientName, phoneNumber, gmail } }
      );
    } else {
      // Insert new info
      await db.collection('account_info').insertOne({ username, region, houseStreet, recipientName, phoneNumber, gmail });
    }

    return res.status(200).json({ message: 'Account info saved successfully.' });
  } catch (err) {
    console.error('Error updating account info:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// Fetch profile picture
app.get('/api/get-profile-picture/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const user = await db.collection('account_info').findOne({ username });

    if (!user || !user.profilePicture) {
      return res.status(404).json({ message: "Profile picture not found." });
    }

    res.status(200).json({ profilePicture: user.profilePicture });
  } catch (err) {
    console.error('Error fetching profile picture:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Update profile 
app.post('/api/update-profile-picture', async (req, res) => {
  try {
    const { username, profilePicture } = req.body;

    if (!username || !profilePicture) {
      return res.status(400).json({ message: 'Username and profile picture URL are required.' });
    }

    const result = await db.collection('account_info').updateOne(
      { username },
      { $set: { profilePicture } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    return res.status(200).json({ message: 'Profile picture updated successfully.' });
  } catch (err) {
    console.error('Error updating profile picture:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// API to get total users count
app.get('/api/total-users', async (req, res) => {
  try {
    const totalUsers = await db.collection('users').countDocuments(); // Count total users
    res.status(200).json({ totalUsers });
  } catch (err) {
    console.error('Error fetching user count:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ---------------------END OF USER INFO--------------------------------

// ---------------------USER CART------------------------
// API to fetch user's cart products
// With available quantity from stocks
app.get('/api/user-cart/:username', async (req, res) => {
  try {
    const { username } = req.params;

    if (!username) {
      return res.status(400).json({ message: 'Username is required.' });
    }

    const userCart = db.collection('userCart');
    const stocks = db.collection('stocks');

    const cartItems = await userCart.find({ username }).toArray();

    const updatedCartItems = await Promise.all(cartItems.map(async item => {
      const stock = await stocks.findOne({ productID: item.productID });
      return {
        ...item,
        availableQuantity: stock?.quantity ?? 0
      };
    }));

    res.status(200).json(updatedCartItems);
  } catch (err) {
    console.error('Error fetching cart items:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// API to add a product to user's cart with Audit trail logs
app.post('/api/add-to-cart', async (req, res) => {
  try {
    const { username, staffUsername, price, productID, product } = req.body;

    if (!username || !product || !product.productName) {
      return res.status(400).json({ message: 'Username and product details are required.' });
    }

    const userCart = db.collection('userCart');
    const auditTrailLogs = db.collection('auditTrailLogs');

    // Check if product already exists in the cart
    const existingItem = await userCart.findOne({
      username,
      'product.productName': product.productName,
      'product.color': product.color,
      'product.size': product.size || null,
      price: price,
    });

    if (existingItem) {
      await userCart.updateOne(
        { _id: existingItem._id },
        { $inc: { quantity: 1 } }
      );
    } else {
      const cartItem = {
        username,
        staffUsername,
        productID,
        price,
        product,
        quantity: 1,
        addedAt: new Date(),
      };
      await userCart.insertOne(cartItem);
    }

    // Fetch full account info
    const accountInfo = await db.collection('account_info').findOne({ username });

    // Insert audit log
    await auditTrailLogs.insertOne({
      username,
      role: "Customer",
      action: "Add to Cart",
      affectedId: productID,
      accountInfo: accountInfo || {},
      timestamp: new Date(),
    });

    res.status(200).json({ message: 'Product added to cart successfully.' });
  } catch (err) {
    console.error('Error adding to cart:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// API to update product quantity in the cart with Audit Trail Logs
app.put('/api/update-cart/:id', async (req, res) => {
  try {
    const { username, quantity } = req.body;
    const cartItemId = req.params.id;

    console.log("Received request to update cart:", req.body);

    if (!username || !cartItemId || quantity < 1) {
      return res.status(400).json({ message: 'Invalid request data.' });
    }

    const userCart = db.collection('userCart');
    const auditLogs = db.collection('auditTrailLogs');
    const accountInfoCollection = db.collection('account_info');

    // Find the specific cart item (to retrieve productID for audit trail)
    const cartItem = await userCart.findOne({ username, _id: new ObjectId(cartItemId) });
    if (!cartItem) {
      return res.status(404).json({ message: 'Product not found in cart.' });
    }

    // Update the cart item
    const result = await userCart.updateOne(
      { username, _id: new ObjectId(cartItemId) },
      { $set: { quantity } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Product not found or not updated.' });
    }

    // Get full user account info
    const accountInfo = await accountInfoCollection.findOne({ username });

    // Insert audit log
    const auditEntry = {
      username,
      action: 'Update Cart Product',
      role: 'Customer',
      affectedId: cartItem.productID, // Log the product ID in the cart
      timestamp: new Date(),
      accountInfo: accountInfo || {},
    };

    await auditLogs.insertOne(auditEntry);

    res.status(200).json({ message: 'Cart updated and audit logged successfully.' });
  } catch (error) {
    console.error('Error updating cart:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// API to delete a product from the cart with Audit Trail Logs
app.delete('/api/delete-cart/:id', async (req, res) => {
  try {
    const { username } = req.body;
    const cartItemId = req.params.id;

    if (!username || !cartItemId) {
      return res.status(400).json({ message: 'Username and Product ID are required.' });
    }

    const userCart = db.collection('userCart');
    const auditLogs = db.collection('auditTrailLogs');
    const accountInfoCollection = db.collection('account_info');

    // Get the productID before deletion for audit log
    const cartItem = await userCart.findOne({ username, _id: new ObjectId(cartItemId) });
    if (!cartItem) {
      return res.status(404).json({ message: 'Product not found in cart.' });
    }

    const result = await userCart.deleteOne({
      username,
      _id: new ObjectId(cartItemId),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'Product not found in cart.' });
    }

    // Get account info for audit log
    const accountInfo = await accountInfoCollection.findOne({ username });

    // Log audit
    const auditEntry = {
      username,
      action: 'Delete Cart Product',
      role: 'Customer',
      affectedId: cartItem.productID,
      timestamp: new Date(),
      accountInfo: accountInfo || {},
    };

    await auditLogs.insertOne(auditEntry);

    res.status(200).json({ message: 'Product removed from cart and audit logged.' });
  } catch (error) {
    console.error('Error deleting cart item:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// --------------------END OF USER CART------------------------

// --------------USER ORDER PROCESS-------------------------
// API to place an order
// app.post('/api/place-order', async (req, res) => {
//   try {
//     const { username, selectedItems, paymentMethod, shippingOptions, totalPrice } = req.body;

//     if (!username || !selectedItems || selectedItems.length === 0 || !paymentMethod) {
//       return res.status(400).json({ message: 'Invalid order request.' });
//     }

//     const userCart2 = db.collection('userCart');
//     const userShippingCollection = db.collection('userShipping');
//     const stocksCollection = db.collection('stocks');
//     const auditLogs = db.collection('auditTrailLogs');
//     const accountInfoCollection = db.collection('account_info');

//     const accountInfo = await accountInfoCollection.findOne({ username });

//     for (const item of selectedItems) {
//       const { _id, quantity, productID } = item;

//       // Move item to userShipping
//       await userShippingCollection.insertOne({
//         username,
//         staffUsername: item.staffUsername,
//         productID: item.productID,
//         productName: item.product.productName,
//         price: totalPrice,
//         quantity: item.quantity,
//         paymentMethod,
//         shippingDate: shippingOptions[item._id] || 'Standard',
//         imageUrl: item.product.imageUrl,
//         orderedAt: new Date(),
//       });

//       // Update product quantity in stocks using productID
//       await stocksCollection.updateOne(
//         { productID: productID },
//         { $inc: { quantity: -quantity } }
//       );

//       // Log audit per item
//       const auditEntry = {
//         username,
//         action: 'Place an Order',
//         role: 'Customer',
//         affectedId: productID,
//         timestamp: new Date(),
//         accountInfo: accountInfo || {},
//       };
//       await auditLogs.insertOne(auditEntry);
//     }

//     // Remove all items from cart
//     await userCart2.deleteMany({
//       username,
//       _id: { $in: selectedItems.map(item => item._id) }
//     });

//     res.status(200).json({ message: 'Order placed successfully and audit logged.' });
//   } catch (error) {
//     console.error("Error placing order:", error);
//     res.status(500).json({ message: 'Failed to place order.' });
//   }
// });


// app.post('/api/place-order', async (req, res) => {
//   try {
//     const { username, selectedItems, paymentMethod, shippingOptions, totalPrice } = req.body;

//     if (!username || !selectedItems || selectedItems.length === 0 || !paymentMethod) {
//       return res.status(400).json({ message: 'Invalid order request.' });
//     }

//     const userCart2 = db.collection('userCart');
//     const userShippingCollection = db.collection('userShipping');
//     const stocksCollection = db.collection('stocks');
//     const auditLogs = db.collection('auditTrailLogs');
//     const accountInfoCollection = db.collection('account_info');

//     const accountInfo = await accountInfoCollection.findOne({ username });

//     for (const item of selectedItems) {
//       const { _id, quantity, productID } = item;

//       // Move item to userShipping
//       await userShippingCollection.insertOne({
//         username,
//         staffUsername: item.staffUsername,
//         productID: item.productID,
//         productName: item.product.productName,
//         price: totalPrice,
//         quantity: item.quantity,
//         paymentMethod,
//         shippingDate: shippingOptions[item._id] || 'Standard',
//         imageUrl: item.product.imageUrl,
//         orderedAt: new Date(),
//       });

//       // Update product quantity in stocks using productID
//       await stocksCollection.updateOne(
//         { productID: productID },
//         { $inc: { quantity: -quantity } }
//       );

//       // Log audit per item
//       const auditEntry = {
//         username,
//         action: 'Place an Order',
//         role: 'Customer',
//         affectedId: productID,
//         timestamp: new Date(),
//         accountInfo: accountInfo || {},
//       };
//       await auditLogs.insertOne(auditEntry);
//     }

//     // Remove all items from cart
//     await userCart2.deleteMany({
//       username,
//       _id: { $in: selectedItems.map(item => item._id) }
//     });

//     const transporter = nodemailer.createTransport({
//       service: 'gmail',
//       auth: {
//         user: "onlineshopmacky@gmail.com",
//         pass: "yiqg icdd jjzh pdvg", // This should be a Gmail App Password (not regular password)
//       },
//       tls: {
//         rejectUnauthorized: false, // Add this line to allow self-signed certificates
//       },
//     });

//     // const mailOptions = {
//     //   from: "onlineshopmacky@gmail.com",
//     //   to: accountInfo.gmail, // User's Gmail address
//     //   subject: 'Order Confirmation',
//     //   text: `Hello ${accountInfo.recipientName},\n\nYour order has been successfully placed!\n\nOrder Details:\n\nTotal Price: ₱${totalPrice}\nPayment Method: ${paymentMethod}\nShipping Address: ${accountInfo.houseStreet}, ${accountInfo.region}\n\nThank you for shopping with us!`,
//     // };
//     const itemDetails = selectedItems.map((item, index) => {
//       return `Item ${index + 1}:
//       - Product: ${item.product.productName}
//       - Price: ₱${item.product.price}
//       - Quantity: ${item.quantity}
//       - Payment Method: ${paymentMethod}
//       - Shipping Date: ${shippingOptions[item._id] || 'Standard'}\n`;
//     }).join('\n');

//     const mailOptions = {
//       from: "onlineshopmacky@gmail.com",
//       to: accountInfo.gmail, // User's Gmail address
//       subject: 'Your Receipt from Macky\'s Online Shop',
//       text: `Hello ${accountInfo.recipientName},

//     Thank you for shopping with us! Your order has been placed successfully.

//     🧾 RECEIPT:

//     ${itemDetails}
//     Total Price: ₱${totalPrice}

//     Shipping Address:
//     ${accountInfo.houseStreet}, ${accountInfo.region}

//     We appreciate your business. Let us know if you have any questions!

//     - Macky’s Online Shop Team`,
//     };    

//     transporter.sendMail(mailOptions, (error, info) => {
//       if (error) {
//         console.log('Error sending email:', error);
//       } else {
//         console.log('Email sent: ' + info.response);
//       }
//     });

//     res.status(200).json({ message: 'Order placed successfully, audit logged, and confirmation email sent.' });
//   } catch (error) {
//     console.error("Error placing order:", error);
//     res.status(500).json({ message: 'Failed to place order.' });
//   }
// });
// Modify 5/8
// Function to generate random userOrderID
function generateOrderID(length = 10) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
app.post('/api/place-order', async (req, res) => {
  try {
    const { username, selectedItems, paymentMethod, shippingOptions, shippingPrice, totalPrice } = req.body;

    if (!username || !selectedItems || selectedItems.length === 0 || !paymentMethod) {
      return res.status(400).json({ message: 'Invalid order request.' });
    }

    const userOrderID = generateOrderID();

    const userCart2 = db.collection('userCart');
    const userShippingCollection = db.collection('userShipping');
    const stocksCollection = db.collection('stocks');
    const auditLogs = db.collection('auditTrailLogs');
    const accountInfoCollection = db.collection('account_info');

    const accountInfo = await accountInfoCollection.findOne({ username });

    for (const item of selectedItems) {
      const { _id, quantity, productID } = item;

      // Move item to userShipping
      await userShippingCollection.insertOne({
        userOrderID,
        username,
        staffUsername: item.staffUsername,
        productID: item.productID,
        productName: item.product.productName,
        price: item.price,
        quantity: item.quantity,
        shippingPrice: shippingPrice,
        paymentMethod,
        shippingDate: shippingOptions[item._id] || 'Standard',
        imageUrl: item.product.imageUrl,
        orderedAt: new Date(),
      });

      // Update product quantity in stocks using productID
      await stocksCollection.updateOne(
        { productID: productID },
        { $inc: { quantity: -quantity } }
      );

      // Log audit per item
      const auditEntry = {
        username,
        action: 'Place an Order',
        role: 'Customer',
        affectedId: productID,
        timestamp: new Date(),
        accountInfo: accountInfo || {},
      };
      await auditLogs.insertOne(auditEntry);
    }

    // Remove all items from cart
    await userCart2.deleteMany({
      username,
      _id: { $in: selectedItems.map(item => item._id) }
    });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: "onlineshopmacky@gmail.com",
        pass: "yiqg icdd jjzh pdvg", // This should be a Gmail App Password (not regular password)
      },
      tls: {
        rejectUnauthorized: false, // Add this line to allow self-signed certificates
      },
    });

    const itemDetails = selectedItems.map((item, index) => {
      const shippingObj = shippingOptions[item._id];
      const shippingDate = shippingObj?.shippingDate
        ? new Date(shippingObj.shippingDate).toLocaleDateString('en-US', {
          weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
        })
        : 'Standard';

      return `Item ${index + 1}:
      - Product: ${item.product.productName}
      - Price: ₱${item.price}
      - Quantity: ${item.quantity}
      - Payment Method: ${paymentMethod}
      - Shipping Date: ${shippingDate}\n`;
    }).join('\n');

    const mailOptions = {
      from: "onlineshopmacky@gmail.com",
      to: accountInfo.gmail, // User's Gmail address
      subject: 'Your Receipt from Macky\'s Online Shop',
      text: `Hello ${accountInfo.recipientName},
    
    Thank you for shopping with us! Your order has been placed successfully.
    
    🧾 RECEIPT:
    
    ${itemDetails}
    Total Price: ₱${totalPrice}
    
    Shipping Address:
    ${accountInfo.houseStreet}, ${accountInfo.region}
    
    If you have any questions regarding your order, feel free to contact our support team.
    
    - Macky’s Online Shop Team`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log('Error sending email:', error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });

    res.status(200).json({ message: 'Order placed successfully, audit logged, and confirmation email sent.' });
  } catch (error) {
    console.error("Error placing order:", error);
    res.status(500).json({ message: 'Failed to place order.' });
  }
});

// API to fetch users' orders
// Needs revision
app.get('/api/user-orders/:username', async (req, res) => {
  try {
    const { username } = req.params;
    if (!username) {
      return res.status(400).json({ message: "Username is required." });
    }

    const userOrders = db.collection('userShipping');
    const toReceive = db.collection('toReceive');

    // Fetch orders
    const orders = await userOrders.find({ username }).toArray();

    const now = new Date();

    // Function to compare only the date (ignoring the time)
    const isSameOrAfter = (a, b) => {
      return (
        a.getFullYear() > b.getFullYear() ||
        (a.getFullYear() === b.getFullYear() && a.getMonth() > b.getMonth()) ||
        (a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() >= b.getDate())
      );
    };

    // Separate orders that should be moved
    const ordersToMove = orders.filter(order => {
      console.log(`Shipping date for order ${order._id}:`, order.shippingDate);

      // Check if shippingDate object and shippingDate string exist
      if (!order.shippingDate || !order.shippingDate.shippingDate) {
        console.error(`Invalid shippingDate for order ${order._id}`);
        return false;
      }

      const shippingDate = new Date(order.shippingDate.shippingDate);

      // Check if parsed date is valid
      if (isNaN(shippingDate.getTime())) {
        console.error(`Invalid shippingDate for order ${order._id}`);
        return false;
      }

      const oneDayBeforeShipping = new Date(shippingDate);
      oneDayBeforeShipping.setDate(shippingDate.getDate() - 1);

      // Debugging logs
      console.log("Now:", now.toISOString());
      console.log("One day before shipping:", oneDayBeforeShipping.toISOString());

      return isSameOrAfter(now, oneDayBeforeShipping);
    });

    // Move qualifying orders
    if (ordersToMove.length > 0) {
      // Insert to toReceive
      await toReceive.insertMany(ordersToMove);

      // Remove from userShipping
      const idsToRemove = ordersToMove.map(order => order._id);
      await userOrders.deleteMany({ _id: { $in: idsToRemove } });
    }

    // Fetch updated orders after moving
    const updatedOrders = await userOrders.find({ username }).toArray();

    if (updatedOrders.length === 0) {
      return res.status(404).json({ message: "No orders found for this user." });
    }

    res.status(200).json(updatedOrders);
  } catch (error) {
    console.error("Error fetching user orders:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Fetch to receive orders
// New endpoint for fetching 'toReceive' orders
app.get('/api/to-receive/:username', async (req, res) => {
  try {
    const { username } = req.params;
    if (!username) {
      return res.status(400).json({ message: "Username is required." });
    }

    const toReceive = db.collection('toReceive');
    const orders = await toReceive.find({ username }).toArray();

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders to receive for this user." });
    }

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching to-receive orders:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Fetch all orders base on user
// Fetch received orders by username
app.get('/api/order-received/:username', async (req, res) => {
  const { username } = req.params;

  try {
    const orders = await db
      .collection('orderReceived')
      .find({ username })
      .toArray();

    if (orders.length === 0) {
      return res.status(404).json({ message: "No received orders found for this user." });
    }

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching received orders by username:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Cancel shipping order with Audit Trail Logs
// app.post('/api/user-cancel-order/:orderId', async (req, res) => {
//   try {
//     const { orderId } = req.params;
//     const { canceledReason } = req.body;

//     if (!orderId || !canceledReason) {
//       return res.status(400).json({ message: "Order ID and reason are required." });
//     }

//     const userShippingCollection = db.collection('userShipping');
//     const stocksCollection = db.collection('stocks');
//     const canceledOrders = db.collection('canceledOrders');
//     const auditLogs = db.collection('auditTrailLogs');
//     const accountInfoCollection = db.collection('account_info');

//     // Find the order
//     const order = await userShippingCollection.findOne({ _id: new ObjectId(orderId) });

//     if (!order) {
//       return res.status(404).json({ message: "Order not found." });
//     }

//     // Restore stock
//     await stocksCollection.updateOne(
//       { productID: order.productID },
//       { $inc: { quantity: order.quantity } }
//     );

//     // Add cancellation info
//     order.canceledReason = canceledReason;
//     order.canceledDate = new Date().toISOString().split('T')[0];

//     // Insert to canceledOrders
//     await canceledOrders.insertOne(order);

//     // Remove from userShipping
//     const result = await userShippingCollection.deleteOne({ _id: new ObjectId(orderId) });

//     if (result.deletedCount === 0) {
//       return res.status(500).json({ message: "Failed to delete the order." });
//     }

//     // Fetch account info for audit
//     const accountInfo = await accountInfoCollection.findOne({ username: order.username });

//     // Add to audit trail
//     const auditEntry = {
//       username: order.username,
//       action: 'Customer canceled the order',
//       role: 'Customer',
//       affectedId: order.productID,
//       timestamp: new Date(),
//       accountInfo: accountInfo || {},
//     };

//     await auditLogs.insertOne(auditEntry);

//     res.status(200).json({ message: "Order cancelled and stock restored successfully." });
//   } catch (error) {
//     console.error("Error cancelling order:", error);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });

app.post('/api/user-cancel-order/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;
    const { canceledReason } = req.body;

    if (!orderId || !canceledReason) {
      return res.status(400).json({ message: "Order ID and reason are required." });
    }

    const userShippingCollection = db.collection('userShipping');
    const stocksCollection = db.collection('stocks');
    const canceledOrders = db.collection('canceledOrders');
    const auditLogs = db.collection('auditTrailLogs');
    const accountInfoCollection = db.collection('account_info');

    // Find the order
    const order = await userShippingCollection.findOne({ _id: new ObjectId(orderId) });

    if (!order) {
      return res.status(404).json({ message: "Order not found." });
    }

    // Restore stock
    await stocksCollection.updateOne(
      { productID: order.productID },
      { $inc: { quantity: order.quantity } }
    );

    // Add cancellation info
    order.canceledReason = canceledReason;
    order.canceledDate = new Date().toISOString().split('T')[0];

    // Insert to canceledOrders
    await canceledOrders.insertOne(order);

    // Remove from userShipping
    const result = await userShippingCollection.deleteOne({ _id: new ObjectId(orderId) });

    if (result.deletedCount === 0) {
      return res.status(500).json({ message: "Failed to delete the order." });
    }

    // Fetch account info for audit
    const accountInfo = await accountInfoCollection.findOne({ username: order.username });

    // Add to audit trail
    const auditEntry = {
      username: order.username,
      action: 'Customer canceled the order',
      role: 'Customer',
      affectedId: order.productID,
      timestamp: new Date(),
      accountInfo: accountInfo || {},
    };

    await auditLogs.insertOne(auditEntry);


    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: "onlineshopmacky@gmail.com",
        pass: "yiqg icdd jjzh pdvg", // This should be a Gmail App Password (not regular password)
      },
      tls: {
        rejectUnauthorized: false, // Add this line to allow self-signed certificates
      },
    });

    // Send cancellation email to customer
    const mailOptions = {
      from: 'onlineshopmacky@gmail.com', // Replace with your email address
      to: accountInfo.gmail, // User's email from the account info
      subject: 'Order Cancellation Confirmation',
      text: `Dear ${accountInfo.username},\n\nYour order (ID: ${orderId}) has been successfully canceled.\n\nReason: ${canceledReason}\n\nBest regards,\nYour Store Name`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log('Error sending email:', error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });

    res.status(200).json({ message: "Order cancelled and stock restored successfully." });
  } catch (error) {
    console.error("Error cancelling order:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// --------------END OF USER ORDER PROCESS-------------------------

app.get('/api/stock/:id', async (req, res) => {
  try {
    const stocksCollection = db.collection('stocks');
    const product = await stocksCollection.findOne({ productID: req.params.id });
    if (!product) return res.status(404).json({ message: 'Product not found' });

    res.json({ quantity: product.quantity });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Fetch all received orders
app.get('/api/all-order-received', async (req, res) => {
  try {
    const orderReceived = await db.collection('orderReceived').find().toArray();

    if (orderReceived.length === 0) {
      return res.status(404).json({ message: "No received orders found." });
    }

    res.status(200).json(orderReceived);
  } catch (error) {
    console.error("Error fetching received orders:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Fetch and insert to Order Received
// Marking order as received with Audit Trail Logs
// app.post('/api/mark-received/:orderId', async (req, res) => {
//   try {
//     const { orderId } = req.params;
//     const { orderReceivedDate, staffUsername } = req.body;

//     if (!orderId || !staffUsername) {
//       return res.status(400).json({ message: "Order ID and staffUsername are required." });
//     }

//     const toReceive = db.collection('toReceive');
//     const orderReceived = db.collection('orderReceived');
//     const staffCollection = db.collection('staff');
//     const auditLogs = db.collection('auditTrailLogs');

//     const order = await toReceive.findOne({ _id: new ObjectId(orderId) });

//     if (!order) {
//       return res.status(404).json({ message: "Order not found in toReceive." });
//     }

//     // Attach received date
//     order.orderReceivedDate = orderReceivedDate || new Date().toISOString().split('T')[0];

//     // Move to orderReceived
//     await orderReceived.insertOne(order);
//     await toReceive.deleteOne({ _id: new ObjectId(orderId) });

//     // Fetch staff info for audit log
//     const staffInfo = await staffCollection.findOne({ username: staffUsername });

//     // Add to audit trail
//     const auditEntry = {
//       username: staffUsername,
//       action: "Staff Marked Order as Received",
//       role: "Staff",
//       affectedId: order.productID,
//       timestamp: new Date(),
//       accountInfo: staffInfo || {},
//     };

//     await auditLogs.insertOne(auditEntry);

//     res.status(200).json({ message: "Order marked as received." });
//   } catch (error) {
//     console.error("Error marking order as received:", error);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });

// Moving orders to received orders
app.post('/api/mark-received', async (req, res) => {
  try {
    const { orderId, orderReceivedDate, staffUsername } = req.body;

    if (!orderId || !staffUsername) {
      return res.status(400).json({ message: "Order ID and staffUsername are required." });
    }

    const toReceive = db.collection('toReceive');
    const orderReceived = db.collection('orderReceived');
    const staffCollection = db.collection('staff');
    const auditLogs = db.collection('auditTrailLogs');

    // Step 1: Find the order by _id to get the userOrderID
    const singleOrder = await toReceive.findOne({ _id: new ObjectId(orderId) });
    if (!singleOrder) return res.status(404).json({ message: "Order not found." });

    const { userOrderID } = singleOrder;

    // Step 2: Find all orders with the same userOrderID
    const relatedOrders = await toReceive.find({ userOrderID }).toArray();

    // Step 3: Set the received date for each order
    const dateToUse = orderReceivedDate || new Date().toISOString().split('T')[0];
    const ordersWithDate = relatedOrders.map(order => ({
      ...order,
      orderReceivedDate: dateToUse
    }));

    // Step 4: Insert them into orderReceived
    await orderReceived.insertMany(ordersWithDate);

    // Step 5: Delete them from toReceive
    await toReceive.deleteMany({ userOrderID });

    // Step 6: Log audit once per userOrderID
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    const auditEntry = {
      username: staffUsername,
      action: `Staff marked all orders for userOrderID ${userOrderID} as received`,
      role: "Staff",
      affectedId: userOrderID,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    };

    await auditLogs.insertOne(auditEntry);

    res.status(200).json({ message: "Order group marked as received." });
  } catch (error) {
    console.error("Error marking order as received:", error.message, error.stack);
    res.status(500).json({ message: "Internal server error." });
  }
});


// Cancel Order with Audit trail logs
app.post('/api/cancel-order/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;
    const { canceledReason, staffUsername } = req.body;

    if (!orderId || !canceledReason || !staffUsername) {
      return res.status(400).json({ message: "Order ID, reason, and staff username are required." });
    }

    const toReceive = db.collection('toReceive');
    const canceledOrders = db.collection('canceledOrders');
    const staffCollection = db.collection('staff');
    const auditLogs = db.collection('auditTrailLogs');

    const order = await toReceive.findOne({ _id: new ObjectId(orderId) });

    if (!order) {
      return res.status(404).json({ message: "Order not found in toReceive." });
    }

    // Add canceled details
    order.canceledReason = canceledReason;
    order.canceledDate = new Date().toISOString().split('T')[0];

    // Move order to canceledOrders
    await canceledOrders.insertOne(order);
    await toReceive.deleteOne({ _id: new ObjectId(orderId) });

    // Fetch staff info for audit trail
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    // Add to audit trail
    const auditEntry = {
      username: staffUsername,
      role: "Staff",
      action: "Staff Canceled Order",
      affectedId: order.productID,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    };

    await auditLogs.insertOne(auditEntry);

    res.status(200).json({ message: "Order canceled successfully." });
  } catch (error) {
    console.error("Error canceling order:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Fetch all canceled orders
app.get('/api/all-canceled-orders', async (req, res) => {
  try {
    const canceledOrders = await db.collection('canceledOrders').find().toArray();

    if (canceledOrders.length === 0) {
      return res.status(404).json({ message: "No canceled orders found." });
    }

    res.status(200).json(canceledOrders);
  } catch (error) {
    console.error("Error fetching canceled orders:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Fetch all canceled order base on user
// Fetch canceled orders by username
app.get('/api/canceled-orders/:username', async (req, res) => {
  const { username } = req.params;

  try {
    const orders = await db
      .collection('canceledOrders')
      .find({ username })
      .toArray();

    if (orders.length === 0) {
      return res.status(404).json({ message: "No canceled orders found for this user." });
    }

    res.status(200).json(orders);
  } catch (error) {
    console.error("Error fetching canceled orders by username:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// --------------------USER REVIEW-------------------
// app.post('/api/submit-review', async (req, res) => {
//   const { orderId, username, productName, rating, review } = req.body;

//   if (!orderId || !username || !productName || !rating || !review) {
//     return res.status(400).json({ message: "Missing fields." });
//   }

//   try {
//     const newReview = {
//       orderId,
//       username,
//       productName,
//       rating,
//       review,
//       createdAt: new Date(),
//     };

//     await db.collection('userReview').insertOne(newReview);
//     res.status(201).json({ message: "Review submitted successfully!" });
//   } catch (error) {
//     console.error("Error inserting review:", error);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });
// app.post('/api/submit-review', async (req, res) => {
//   const { orderId, productID, username, productName, rating, review, accountInfo } = req.body;

//   if (!orderId || !productID || !username || !productName || !rating || !review || !accountInfo) {
//     return res.status(400).json({ message: "Missing fields." });
//   }

//   try {
//     const newReview = {
//       orderId,
//       productID,
//       username,
//       productName,
//       rating,
//       review,
//       accountInfo, // Include detailed account info
//       createdAt: new Date(),
//     };

//     await db.collection('userReview').insertOne(newReview);
//     res.status(201).json({ message: "Review submitted successfully!" });
//   } catch (error) {
//     console.error("Error inserting review:", error);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });
// With photo
app.post('/api/submit-review', async (req, res) => {
  const { orderId, productID, username, productName, rating, review, accountInfo, reviewImageUrl } = req.body; // <-- added reviewImageUrl

  if (!orderId || !productID || !username || !productName || !rating || !review || !accountInfo) {
    return res.status(400).json({ message: "Missing fields." });
  }

  try {
    const newReview = {
      orderId,
      productID,
      username,
      productName,
      rating,
      review,
      accountInfo,
      reviewImageUrl: reviewImageUrl || null,  // <-- Save image URL if exists
      createdAt: new Date(),
    };

    await db.collection('userReview').insertOne(newReview);
    res.status(201).json({ message: "Review submitted successfully!" });
  } catch (error) {
    console.error("Error inserting review:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// app.put('/api/update-review', async (req, res) => {
//   const { orderId, productID, username, productName, rating, review, accountInfo } = req.body;

//   if (!orderId || !productID || !username || !productName || !rating || !review || !accountInfo) {
//     return res.status(400).json({ message: "Missing fields." });
//   }

//   try {
//     const updatedReview = {
//       rating,
//       review,
//       updatedAt: new Date(),
//     };

//     await db.collection('userReview').updateOne(
//       { orderId, username },
//       { $set: updatedReview }
//     );

//     res.status(200).json({ message: "Review updated successfully!" });
//   } catch (error) {
//     console.error("Error updating review:", error);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });

// WIth photo

app.put('/api/update-review', async (req, res) => {
  const { orderId, productID, username, productName, rating, review, accountInfo, reviewImageUrl } = req.body; // <-- added reviewImageUrl

  if (!orderId || !productID || !username || !productName || !rating || !review || !accountInfo) {
    return res.status(400).json({ message: "Missing fields." });
  }

  try {
    const updatedReview = {
      rating,
      review,
      updatedAt: new Date(),
      ...(reviewImageUrl && { reviewImageUrl }), // <-- only update image if it exists
    };

    await db.collection('userReview').updateOne(
      { orderId, username },
      { $set: updatedReview }
    );

    res.status(200).json({ message: "Review updated successfully!" });
  } catch (error) {
    console.error("Error updating review:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// app.get("/api/review/:orderId/:username", async (req, res) => {
//   const { orderId, username } = req.params;

//   try {
//     const review = await db.collection("userReview").findOne({ orderId, username });

//     if (review) {
//       res.status(200).json({ hasReviewed: true, review });
//     } else {
//       res.status(404).json({ hasReviewed: false });
//     }
//   } catch (error) {
//     console.error("Error fetching review:", error);
//     res.status(500).json({ message: "Internal server error" });
//   }
// });

// app.get('/api/review/:orderId/:username', async (req, res) => {
//   const { orderId, username } = req.params;

//   try {
//     const review = await db.collection('userReview').findOne({ orderId, username });

//     if (review) {
//       res.json({
//         hasReviewed: true,
//         review: {
//           rating: review.rating,
//           review: review.review,
//         },
//       });
//     } else {
//       res.json({ hasReviewed: false });
//     }
//   } catch (error) {
//     console.error("Error fetching review:", error);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });
// With photo
app.get('/api/review/:orderId/:username', async (req, res) => {
  const { orderId, username } = req.params;

  try {
    const review = await db.collection('userReview').findOne({ orderId, username });

    if (review) {
      res.json({
        hasReviewed: true,
        review: {
          rating: review.rating,
          review: review.review,
          reviewImageUrl: review.reviewImageUrl || null, // <-- Add this line
        },
      });
    } else {
      res.json({ hasReviewed: false });
    }
  } catch (error) {
    console.error("Error fetching review:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// user homepage review
// ✨ New API to fetch all reviews for a productID
app.get('/api/reviews-by-product/:productID', async (req, res) => {
  const { productID } = req.params;

  try {
    const reviews = await db.collection('userReview').find({ productID }).toArray();
    res.json(reviews);
  } catch (error) {
    console.error("Error fetching reviews:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});



// --------------------------------- STAFF ------------------------------
// ------------------STAFF ACCOUNT-----------------------
// API to log in as Staff
app.post('/api/staffLogin', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Find user by username
    const user = await db.collection('staff').findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Generate token
    const token = generateToken(user);

    // Login successful, send token
    return res.status(200).json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Error during login:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// API to create a staff account
app.post('/api/staffSignup', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Check if the user already exists
    const existingUser = await db.collection('staff').findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: 'Account already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user
    await db.collection('staff').insertOne({ username, password: hashedPassword });
    return res.status(201).json({ message: 'Account created successfully.' });
  } catch (err) {
    console.error('Error creating account:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// Change password
app.post("/api/change-password", async (req, res) => {
  try {
    const { username, oldPassword, newPassword } = req.body;

    if (!username || !oldPassword || !newPassword) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const user = await db.collection("staff").findOne({ username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Incorrect old password." });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await db.collection("staff").updateOne({ username }, { $set: { password: hashedNewPassword } });

    res.status(200).json({ message: "Password changed successfully." });
  } catch (err) {
    console.error("Error changing password:", err);
    res.status(500).json({ message: "Internal server error." });
  }
});

// API to get total staff count
app.get('/api/total-staff', async (req, res) => {
  try {
    const totalUsers = await db.collection('staff').countDocuments(); // Count total users
    res.status(200).json({ totalUsers });
  } catch (err) {
    console.error('Error fetching user count:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ------------------END OF STAFF ACCOUNT-----------------------

// -----------------STAFF ACCOUNT INFO----------------------
// Fetch staff account info
app.get('/api/staff-info/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const staff = await db.collection('staff').findOne({ username });
    if (!staff) {
      return res.status(404).json({ message: 'Staff not found.' });
    }
    res.status(200).json({
      staffFullname: staff.staffFullname || '',
      email: staff.email || '',
      region: staff.region || '',
      houseStreet: staff.houseStreet || '',
      phoneNumber: staff.phoneNumber || '',
      contactPerson: staff.contactPerson || '',
    });
  } catch (err) {
    console.error('Error fetching staff info:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Update staff account info
app.post('/api/update-staffAccount', async (req, res) => {
  try {
    const { staffUsername, staffFullname, email, region, houseStreet, phoneNumber, contactPerson, newPassword } = req.body;

    if (!staffUsername) {
      return res.status(400).json({ message: 'Username is required.' });
    }

    const updateData = { staffFullname, email, region, houseStreet, phoneNumber, contactPerson };

    // If new password is provided, hash it before saving
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateData.password = hashedPassword;
    }

    const result = await db.collection('staff').updateOne(
      { username: staffUsername },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'Staff not found.' });
    }

    res.status(200).json({ message: 'Account updated successfully.' });
  } catch (err) {
    console.error('Error updating staff account:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Update Staff profile 
app.post('/api/update-staffprofile-picture', async (req, res) => {
  try {
    const { username, profilePicture } = req.body;

    if (!username || !profilePicture) {
      return res.status(400).json({ message: 'Username and profile picture URL are required.' });
    }

    const result = await db.collection('staff').updateOne(
      { username },
      { $set: { profilePicture } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    return res.status(200).json({ message: 'Profile picture updated successfully.' });
  } catch (err) {
    console.error('Error updating profile picture:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// Fetch profile Staff picture
app.get('/api/get-staffprofile-picture/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const user = await db.collection('staff').findOne({ username });

    if (!user || !user.profilePicture) {
      return res.status(404).json({ message: "Profile picture not found." });
    }

    res.status(200).json({ profilePicture: user.profilePicture });
  } catch (err) {
    console.error('Error fetching profile picture:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// -----------------END OF STAFF ACCOUNT INFO----------------------

// --------------STAFF PRODUCT CATEGORY API------------------------
// Product Maintenance Collection
const productMaintenanceCollection = () => db.collection("productMaintenance");

// Add a new category maintenance with Audit Trail Logs
app.post('/api/product-maintenance', async (req, res) => {
  try {
    let { category, subCategory, brand, color, sizes, staffUsername } = req.body;

    if (!staffUsername) {
      return res.status(400).json({ message: "Staff username is required." });
    }

    // Ensure all fields are arrays
    category = Array.isArray(category) ? category : [category];
    subCategory = Array.isArray(subCategory) ? subCategory : [subCategory];
    brand = Array.isArray(brand) ? brand : [brand];
    color = Array.isArray(color) ? color : [color];
    sizes = Array.isArray(sizes) ? sizes : [sizes];

    const newEntry = { category, subCategory, brand, color, sizes };
    const result = await productMaintenanceCollection().insertOne(newEntry);

    // Fetch staff info
    const staffCollection = db.collection('staff');
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    // Insert audit trail log
    const auditLogs = db.collection('auditTrailLogs');
    await auditLogs.insertOne({
      username: staffUsername,
      role: "Staff",
      action: "Staff Added New Category",
      affectedId: null, // No specific ID affected
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    res.status(201).json(result);
  } catch (error) {
    console.error("Error in product maintenance:", error);
    res.status(500).json({ error: "Failed to add product maintenance data." });
  }
});

// Update product maintenance with Audit Trail Logs
app.put('/api/product-maintenance/:id', async (req, res) => {
  try {
    const { id } = req.params;
    let { category, subCategory, brand, color, sizes, staffUsername } = req.body;

    if (!staffUsername) {
      return res.status(400).json({ error: "Staff username is required for audit logging." });
    }

    // Ensure all fields are arrays
    category = Array.isArray(category) ? category : [category];
    subCategory = Array.isArray(subCategory) ? subCategory : [subCategory];
    brand = Array.isArray(brand) ? brand : [brand];
    color = Array.isArray(color) ? color : [color];
    sizes = Array.isArray(sizes) ? sizes : [sizes];

    const updatedEntry = { category, subCategory, brand, color, sizes };
    const result = await productMaintenanceCollection().updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedEntry }
    );

    // // Audit Logging
    // const staff = await db.collection('staff').findOne({ username: staffUsername });
    // if (staff) {
    //   await db.collection('auditTrailLogs').insertOne({
    //     staffFullname: staff.staffFullname,
    //     staffUsername,
    //     role: "Staff",
    //     action: 'Staff Update Product Category',
    //     affectedId: id,
    //     timestamp: new Date()
    //   });
    // }

    // Fetch staff info
    const staffCollection = db.collection('staff');
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    // Insert audit trail log
    const auditLogs = db.collection('auditTrailLogs');
    await auditLogs.insertOne({
      username: staffUsername,
      role: "Staff",
      action: 'Staff Update Product Category',
      affectedId: id,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    res.status(200).json(result);
  } catch (error) {
    console.error("Error updating product maintenance:", error);
    res.status(500).json({ error: "Failed to update product maintenance data." });
  }
});

// Delete product maintenance with Audit Trail Logs
app.delete('/api/product-maintenance/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { staffUsername } = req.body;

    if (!staffUsername) {
      return res.status(400).json({ error: "Staff username is required for audit logging." });
    }

    // Delete the product category
    const result = await productMaintenanceCollection().deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Product category not found." });
    }

    // // Audit Logging
    // const staff = await db.collection('staff').findOne({ username: staffUsername });
    // if (staff) {
    //   await db.collection('auditTrailLogs').insertOne({
    //     staffFullname: staff.staffFullname,
    //     staffUsername,
    //     role: "Staff",
    //     action: 'Staff Delete Product Category',
    //     affectedId: id,
    //     timestamp: new Date()
    //   });
    // }

    // Fetch staff info
    const staffCollection = db.collection('staff');
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    // Insert audit trail log
    const auditLogs = db.collection('auditTrailLogs');
    await auditLogs.insertOne({
      username: staffUsername,
      role: "Staff",
      action: 'Staff Delete Product Category',
      affectedId: id,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    res.status(200).json({ message: "Product category deleted successfully." });
  } catch (error) {
    console.error("Error deleting product maintenance entry:", error);
    res.status(500).json({ error: "Failed to delete product maintenance data." });
  }
});

// ----------END OF STAFF PRODUCT CATEGORY API---------------------

// -------------STAFF PRODUCT API-------------------------------------
// Add a new product with Audit Trail Logs
// app.post('/api/add-product', async (req, res) => {
//   try {
//     const { staffUsername, productName, category, subCategory, brand, gender, size, color, imageUrl } = req.body;

//     if (!productName || !category || !brand || !color || !imageUrl || !staffUsername) {
//       return res.status(400).json({ message: 'Missing required fields or staff username.' });
//     }

//     const newProduct = {
//       staffUsername,
//       productName,
//       category,
//       subCategory: subCategory?.trim() || null,
//       brand,
//       gender: gender?.trim() || null,
//       size: size?.trim() || null,
//       color,
//       imageUrl,
//       createdAt: new Date(),
//     };

//     await db.collection('products').insertOne(newProduct);

//     // Fetch staff info
//     const staffCollection = db.collection('staff');
//     const staffInfo = await staffCollection.findOne({ username: staffUsername });

//     // Insert audit trail log
//     const auditLogs = db.collection('auditTrailLogs');
//     await auditLogs.insertOne({
//       username: staffUsername,
//       role: "Staff",
//       action: 'Staff Added New Product',
//       affectedId: null,
//       timestamp: new Date(),
//       accountInfo: staffInfo || {},
//     });

//     return res.status(201).json({ message: 'Product added successfully.' });
//   } catch (err) {
//     console.error('Error adding product:', err);
//     return res.status(500).json({ message: 'Internal server error.' });
//   }
// });
// Add a new product with productID
// app.post('/api/add-product', async (req, res) => {
//   try {
//     const { staffUsername, productID, productName, category, subCategory, brand, gender, size, color, imageUrl } = req.body;

//     if (!productName || !category || !brand || !color || !imageUrl || !staffUsername) {
//       return res.status(400).json({ message: 'Missing required fields or staff username.' });
//     }

//     const newProduct = {
//       staffUsername,
//       productID,
//       productName,
//       category,
//       subCategory: subCategory?.trim() || null,
//       brand,
//       gender: gender?.trim() || null,
//       size: size?.trim() || null,
//       color,
//       imageUrl,
//       createdAt: new Date(),
//     };

//     await db.collection('products').insertOne(newProduct);

//     // Fetch staff info
//     const staffCollection = db.collection('staff');
//     const staffInfo = await staffCollection.findOne({ username: staffUsername });

//     // Insert audit trail log
//     const auditLogs = db.collection('auditTrailLogs');
//     await auditLogs.insertOne({
//       username: staffUsername,
//       role: "Staff",
//       action: 'Staff Added New Product',
//       affectedId: null,
//       timestamp: new Date(),
//       accountInfo: staffInfo || {},
//     });

//     return res.status(201).json({ message: 'Product added successfully.' });
//   } catch (err) {
//     console.error('Error adding product:', err);
//     return res.status(500).json({ message: 'Internal server error.' });
//   }
// });
// With multiple images
app.post('/api/add-product', async (req, res) => {
  try {
    const {
      staffUsername,
      productID,
      productName,
      category,
      subCategory,
      brand,
      sex,
      size,
      color,
      imageUrls
    } = req.body; // imageUrls is now an array

    if (!productName || !category || !brand || !color || !imageUrls) {
      return res.status(400).json({ message: 'Missing required fields or staff username.' });
    }

    // Make sure imageUrls is an array of strings
    if (!Array.isArray(imageUrls) || imageUrls.length === 0) {
      return res.status(400).json({ message: 'Please provide at least one image URL.' });
    }

    // Process product data
    const newProduct = {
      staffUsername: staffUsername || null,
      productID,
      productName,
      category,
      subCategory: subCategory?.trim() || null,
      sex,
      brand,
      size: size?.trim() || null,
      color,
      imageUrls, // Store the array of image URLs
      createdAt: new Date(),
    };

    // Insert new product into database
    await db.collection('products').insertOne(newProduct);

    // Fetch staff info
    const staffCollection = db.collection('staff');
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    // Insert audit trail log
    const auditLogs = db.collection('auditTrailLogs');
    await auditLogs.insertOne({
      username: staffUsername,
      role: "Staff",
      action: 'Staff Added New Product',
      affectedId: null,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    return res.status(201).json({ message: 'Product added successfully.' });
  } catch (err) {
    console.error('Error adding product:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// Update product with Audit Trail Logs
// app.put('/api/update-product/:id', async (req, res) => {
//   try {
//     const productId = req.params.id;
//     const { productName, category, subCategory, gender, size, color, imageUrl, staffUsername } = req.body;

//     if (!productId) {
//       return res.status(400).json({ message: 'Product ID is required.' });
//     }

//     if (!staffUsername) {
//       return res.status(400).json({ message: 'Staff username is required for audit logging.' });
//     }

//     const updatedProduct = {
//       ...(productName && { productName }),
//       ...(category && { category }),
//       ...(subCategory && { subCategory }),
//       ...(gender && { gender }),
//       ...(size && { size }),
//       ...(color && { color }),
//       ...(imageUrl && { imageUrl }),
//       updatedAt: new Date(),
//     };

//     const result = await db.collection('products').updateOne(
//       { _id: new ObjectId(productId) },
//       { $set: updatedProduct }
//     );

//     if (result.modifiedCount === 0) {
//       return res.status(404).json({ message: 'Product not found or no changes made.' });
//     }

//     // // Audit Trail Logging
//     // const staff = await db.collection('staff').findOne({ username: staffUsername });
//     // if (staff) {
//     //   await db.collection('auditTrailLogs').insertOne({
//     //     staffFullname: staff.staffFullname,
//     //     staffUsername,
//     //     role: "Staff",
//     //     action: 'Staff Updated Product',
//     //     affectedId: productId,
//     //     timestamp: new Date()
//     //   });
//     // }

//     // Fetch staff info
//     const staffCollection = db.collection('staff');
//     const staffInfo = await staffCollection.findOne({ username: staffUsername });

//     // Insert audit trail log
//     const auditLogs = db.collection('auditTrailLogs');
//     await auditLogs.insertOne({
//       username: staffUsername,
//       role: "Staff",
//       action: 'Staff Updated Product',
//       affectedId: productId,
//       timestamp: new Date(),
//       accountInfo: staffInfo || {},
//     });

//     return res.status(200).json({ message: 'Product updated successfully.' });
//   } catch (err) {
//     console.error('Error updating product:', err);
//     return res.status(500).json({ message: 'Internal server error.' });
//   }
// });
// With multiple images
app.put('/api/update-product/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    const {
      productName,
      category,
      subCategory,
      brand,
      size,
      color,
      sex,
      imageUrls, // ✅ Expecting an array
      staffUsername
    } = req.body;

    if (!productId) {
      return res.status(400).json({ message: 'Product ID is required.' });
    }

    if (!staffUsername) {
      return res.status(400).json({ message: 'Staff username is required for audit logging.' });
    }

    const updatedProduct = {
      ...(productName && { productName }),
      ...(category && { category }),
      ...(subCategory && { subCategory }),
      ...(brand && { brand }),
      ...(size && { size }),
      ...(color && { color }),
      ...(sex && { sex }),
      ...(imageUrls && { imageUrls }), // ✅ Now supports multiple images
      updatedAt: new Date(),
    };

    const result = await db.collection('products').updateOne(
      { _id: new ObjectId(productId) },
      { $set: updatedProduct }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Product not found or no changes made.' });
    }

    // Fetch staff info for audit log
    const staffCollection = db.collection('staff');
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    // Insert audit trail log
    const auditLogs = db.collection('auditTrailLogs');
    await auditLogs.insertOne({
      username: staffUsername,
      role: "Staff",
      action: 'Staff Updated Product',
      affectedId: productId,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    return res.status(200).json({ message: 'Product updated successfully.' });
  } catch (err) {
    console.error('Error updating product:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});


// Remove products with Audit Trail Logs
app.delete('/api/delete-product/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    const { staffUsername } = req.body;

    if (!productId) {
      return res.status(400).json({ message: "Product ID is required." });
    }

    if (!staffUsername) {
      return res.status(400).json({ message: "Staff username is required for audit logging." });
    }

    const result = await db.collection('products').deleteOne({ _id: new ObjectId(productId) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Product not found." });
    }

    // // Audit Trail Logging
    // const staff = await db.collection('staff').findOne({ username: staffUsername });
    // if (staff) {
    //   await db.collection('auditTrailLogs').insertOne({
    //     staffFullname: staff.staffFullname,
    //     staffUsername,
    //     role: "Staff",
    //     action: 'Staff Deleted a Product',
    //     affectedId: productId,
    //     timestamp: new Date()
    //   });
    // }

    // Fetch staff info
    const staffCollection = db.collection('staff');
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    // Insert audit trail log
    const auditLogs = db.collection('auditTrailLogs');
    await auditLogs.insertOne({
      username: staffUsername,
      role: "Staff",
      action: 'Staff Deleted a Product',
      affectedId: productId,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    return res.status(200).json({ message: "Product deleted successfully." });
  } catch (err) {
    console.error("Error deleting product:", err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// ------------------ END OF STAFF PRODUCT API-------------------------

// -------------STAFF DELIVERY API------------------------------
// DELIVERY PRODUCT
// Staff Add new delivery products with Audit Trail Logs
app.post('/api/add-delivery', async (req, res) => {
  try {
    const { productId, supplierId, supplierPrice, shopPrice, quantity, totalCost, staffUsername } = req.body;

    if (!productId || !supplierId || !supplierPrice || !shopPrice || !quantity) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const product = await db.collection('products').findOne({ _id: new ObjectId(productId) });
    const supplier = await db.collection('suppliers').findOne({ _id: new ObjectId(supplierId) });

    if (!product || !supplier) {
      return res.status(404).json({ message: "Product or Supplier not found." });
    }

    const randomProductID = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8-char ID like 'A1B2C3D4'

    // Explicitly set staffUsername to null if it's not provided or is an empty string
    const validStaffUsername = staffUsername && staffUsername.trim() ? staffUsername : null;

    const newDelivery = {
      productID: randomProductID,
      product: {
        productName: product.productName,
        category: product.category,
        subCategory: product.subCategory,
        brand: product.brand,
        gender: product.gender || null,
        size: product.size || null,
        color: product.color,
        imageUrl: product.imageUrl,
      },
      supplier: {
        name: supplier.name,
        contactPerson: supplier.contactPerson,
        email: supplier.email,
        region: supplier.region,
        houseStreet: supplier.houseStreet,
        phone: supplier.phone,
      },
      supplierPrice,
      shopPrice,
      quantity,
      totalCost,
      staffUsername: validStaffUsername,
      addedAt: new Date(),
    };

    await db.collection('deliveries').insertOne(newDelivery);

    // Fetch staff info
    const staffCollection = db.collection('staff');
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    // Insert audit trail log
    const auditLogs = db.collection('auditTrailLogs');
    await auditLogs.insertOne({
      username: staffUsername,
      role: "Staff",
      action: "Staff Added New Delivery Products",
      affectedId: null,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    res.status(201).json({ message: "Delivery added successfully." });
  } catch (err) {
    console.error("Error adding delivery:", err);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Restocks to deliver
app.post('/api/restocks', async (req, res) => {
  try {
    const { stockId, supplierId, supplierPrice, shopPrice, quantity, staffUsername } = req.body;

    if (!stockId || !supplierId || !supplierPrice || !shopPrice || !quantity) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    // Find stock and supplier
    const stock = await db.collection('stocks').findOne({ _id: new ObjectId(stockId) });
    const supplier = await db.collection('suppliers').findOne({ _id: new ObjectId(supplierId) });

    if (!stock || !supplier) {
      return res.status(404).json({ message: "Stock or Supplier not found." });
    }

    const newDelivery = {
      deliveryID: stock.deliveryID,
      productID: stock.productID,
      product: stock.product,
      supplier: supplier,
      supplierPrice,
      shopPrice,
      quantity,
      totalCost: supplierPrice * quantity,
      addedAt: new Date(),
    };

    // Insert into deliveries
    await db.collection('deliveries').insertOne(newDelivery);

    // Fetch staff info
    const staffCollection = db.collection('staff');
    const staffInfo = await staffCollection.findOne({ username: staffUsername });

    // Insert audit trail log
    const auditLogs = db.collection('auditTrailLogs');
    await auditLogs.insertOne({
      username: staffUsername,
      role: "Staff",
      action: "Staff Restock a Product",
      affectedId: stock.productID || null,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    res.status(201).json({ message: "Restock added to deliveries." });
  } catch (err) {
    console.error('Error restocking product:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ADD STOCKS + DELIVERY HISTORY + AUDIT
// app.post('/api/set-as-delivered/:id', async (req, res) => {
//   try {
//     const deliveryId = req.params.id;
//     const { staffUsername } = req.body; // ✅ Extract staffUsername from the request body

//     if (!staffUsername) {
//       return res.status(400).json({ message: "Staff username is required." });
//     }

//     // Find the delivery by ID
//     const delivery = await db.collection('deliveries').findOne({ _id: new ObjectId(deliveryId) });

//     if (!delivery) {
//       return res.status(404).json({ message: "Delivery not found" });
//     }

//     const stocksCollection = db.collection('stocks');

//     // Check if stock with this productID already exists
//     const existingStock = await stocksCollection.findOne({ productID: delivery.productID });

//     if (existingStock) {
//       // Update supplierPrice, shopPrice, and increment quantity
//       await stocksCollection.updateOne(
//         { productID: delivery.productID },
//         {
//           $set: {
//             supplierPrice: delivery.supplierPrice,
//             shopPrice: delivery.shopPrice,
//           },
//           $inc: {
//             quantity: delivery.quantity
//           }
//         }
//       );
//     } else {
//       // Insert new stock record
//       const newStock = {
//         productID: delivery.productID,
//         product: delivery.product,
//         supplier: delivery.supplier,
//         supplierPrice: delivery.supplierPrice,
//         shopPrice: delivery.shopPrice,
//         quantity: delivery.quantity,
//         totalCost: delivery.totalCost,
//         staffUsername: delivery.staffUsername,
//         deliveredAt: new Date()
//       };

//       await stocksCollection.insertOne(newStock);
//     }

//     // Always insert into delivery_history
//     await db.collection('delivery_history').insertOne({
//       ...delivery,
//       deliveredAt: new Date()
//     });

//     // Remove from deliveries
//     await db.collection('deliveries').deleteOne({ _id: new ObjectId(deliveryId) });

//     // Fetch staff info
//     const staffCollection = db.collection('staff');
//     const staffInfo = await staffCollection.findOne({ username: staffUsername });

//     // Insert audit trail log
//     const auditLogs = db.collection('auditTrailLogs');
//     await auditLogs.insertOne({
//       username: staffUsername,
//       role: "Staff",
//       action: "Staff Set a Delivered Products",
//       affectedId: delivery.productID || null,
//       timestamp: new Date(),
//       accountInfo: staffInfo || {},
//     });

//     res.status(200).json({ message: "Set as delivered, moved to stock, and saved to history." });
//   } catch (err) {
//     console.error("Error setting as delivered:", err);
//     res.status(500).json({ message: "Internal server error" });
//   }
// });
// app.post('/api/set-as-delivered/:id', async (req, res) => {
//   try {
//     const deliveryId = req.params.id;
//     const { staffUsername } = req.body;

//     console.log(deliveryId);

//     if (!staffUsername) {
//       return res.status(400).json({ message: "Staff username is required." });
//     }

//     const delivery = await db.collection('deliveries').findOne({ _id: new ObjectId(deliveryId) });

//     if (!delivery) {
//       return res.status(404).json({ message: "Delivery not found" });
//     }

//     const stocksCollection = db.collection('stocks');

//     // ✅ Check if this deliveryID has already been used in stocks
//     const existingByDeliveryID = await stocksCollection.findOne({ deliveryID: delivery.deliveryID });

//     if (!existingByDeliveryID) {
//       // ✅ Either insert new or update by deliveryID
//       const existingStock = await stocksCollection.findOne({ deliveryID: delivery.deliveryID });

//       if (existingStock) {
//         await stocksCollection.updateOne(
//           { deliveryID: delivery.deliveryID },
//           {
//             $set: {
//               supplierPrice: delivery.supplierPrice,
//               shopPrice: delivery.shopPrice,
//             },
//             $inc: {
//               quantity: delivery.quantity
//             }
//           }
//         );
//       } else {
//         // ✅ Insert as new stock
//         await stocksCollection.insertOne({
//           deliveryID: delivery.deliveryID,
//           productID: delivery.productID,
//           product: delivery.product,
//           supplier: delivery.supplier,
//           supplierPrice: delivery.supplierPrice,
//           shopPrice: delivery.shopPrice,
//           quantity: delivery.quantity,
//           totalCost: delivery.totalCost,
//           staffUsername: delivery.staffUsername,
//           deliveredAt: new Date()
//         });
//       }

//       // ✅ Always insert into delivery history
//       await db.collection('delivery_history').insertOne({
//         ...delivery,
//         deliveredAt: new Date()
//       });

//       // ✅ Remove from deliveries
//       await db.collection('deliveries').deleteOne({ _id: new ObjectId(deliveryId) });

//       // ✅ Log the audit trail
//       const staffInfo = await db.collection('staff').findOne({ username: staffUsername });
//       await db.collection('auditTrailLogs').insertOne({
//         username: staffUsername,
//         role: "Staff",
//         action: "Staff Set a Delivered Product",
//         affectedId: delivery.productID,
//         timestamp: new Date(),
//         accountInfo: staffInfo || {},
//       });

//       return res.status(200).json({ message: "Set as delivered, added to stock, and logged to history." });

//     } else {
//       return res.status(409).json({ message: "This delivery has already been processed into stocks." });
//     }

//   } catch (err) {
//     console.error("Error setting as delivered:", err);
//     res.status(500).json({ message: "Internal server error" });
//   }
// });

app.post('/api/set-as-delivered/:id', async (req, res) => {
  try {
    const deliveryId = req.params.id;
    const { staffUsername } = req.body;

    if (!staffUsername) {
      return res.status(400).json({ message: "Staff username is required." });
    }

    // Find the delivery from the deliveries collection
    const delivery = await db.collection('deliveries').findOne({ _id: new ObjectId(deliveryId) });

    if (!delivery) {
      return res.status(404).json({ message: "Delivery not found." });
    }

    const stocksCollection = db.collection('stocks');

    // Check if the delivery has already been processed into stocks
    const existingStock = await stocksCollection.findOne({ deliveryID: delivery.deliveryID });

    if (existingStock) {
      // If it exists, update the stock
      await stocksCollection.updateOne(
        { deliveryID: delivery.deliveryID },
        {
          $set: {
            supplierPrice: delivery.supplierPrice,
            shopPrice: delivery.shopPrice,
          },
          $inc: {
            quantity: delivery.quantity, // increment the stock quantity
          },
        }
      );
    } else {
      // If it doesn't exist, insert a new stock record
      await stocksCollection.insertOne({
        deliveryID: delivery.deliveryID,
        productID: delivery.productID,
        product: delivery.product,
        supplier: delivery.supplier,
        supplierPrice: delivery.supplierPrice,
        shopPrice: delivery.shopPrice,
        quantity: delivery.quantity,
        totalCost: delivery.totalCost,
        staffUsername: delivery.staffUsername,
        deliveredAt: new Date(),
      });
    }

    // Insert into delivery history
    await db.collection('delivery_history').insertOne({
      ...delivery,
      deliveredAt: new Date(),
    });

    // Remove the delivery from the deliveries collection
    await db.collection('deliveries').deleteOne({ _id: new ObjectId(deliveryId) });

    // Log the audit trail
    const staffInfo = await db.collection('staff').findOne({ username: staffUsername });
    await db.collection('auditTrailLogs').insertOne({
      username: staffUsername,
      role: 'Staff',
      action: 'Staff Set a Delivered Product',
      affectedId: delivery.productID,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    return res.status(200).json({ message: "Set as delivered, added to stock, and logged to history." });
  } catch (err) {
    console.error('Error setting as delivered:', err);
    res.status(500).json({ message: "Internal server error" });
  }
});


// ----------==---END OF STAFF DELIVERY API------------------------------

// -----------------SUPPLIER-------------------------
// app.post('/api/add-supplier', async (req, res) => {
//   try {
//     const { name, contactPerson, email, region, houseStreet, phone, staffUsername } = req.body;

//     if (!name || !contactPerson || !email || !region || !houseStreet || !phone || !staffUsername) {
//       return res.status(400).json({ message: "All fields including staffUsername are required." });
//     }

//     // Check if the supplier name already exists in the database
//     const existingSupplier = await db.collection('suppliers').findOne({ name });
//     if (existingSupplier) {
//       return res.status(400).json({ message: "Supplier name must be unique." });
//     }

//     const newSupplier = {
//       name,
//       contactPerson,
//       email,
//       region,
//       houseStreet,
//       phone,
//       staffUsername,
//       createdAt: new Date(),
//     };

//     await db.collection('suppliers').insertOne(newSupplier);
//     return res.status(201).json({ message: "Supplier added successfully." });
//   } catch (err) {
//     console.error("Error adding supplier:", err);
//     return res.status(500).json({ message: "Internal server error." });
//   }
// });

// ADDING Supplier with supplierID
app.post('/api/add-supplier', async (req, res) => {
  try {
    const { name, contactPerson, email, region, houseStreet, phone, staffUsername, supplierID } = req.body;

    if (!name || !contactPerson || !email || !region || !houseStreet || !phone || !staffUsername || !supplierID) {
      return res.status(400).json({ message: "All fields including supplierID are required." });
    }

    // Check if the supplier name already exists in the database
    const existingSupplier = await db.collection('suppliers').findOne({ name });
    if (existingSupplier) {
      return res.status(400).json({ message: "Supplier name must be unique." });
    }

    const newSupplier = {
      supplierID, // 👈 Add supplierID into the document
      name,
      contactPerson,
      email,
      region,
      houseStreet,
      phone,
      staffUsername,
      createdAt: new Date(),
    };

    await db.collection('suppliers').insertOne(newSupplier);
    return res.status(201).json({ message: "Supplier added successfully." });
  } catch (err) {
    console.error("Error adding supplier:", err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// NOT NEEDED ANYMORE
app.post('/api/check-supplier-name', async (req, res) => {
  try {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Supplier name is required." });
    }

    // Check if the supplier name already exists in the database
    const existingSupplier = await db.collection('suppliers').findOne({ name });
    if (existingSupplier) {
      return res.status(400).json({ message: "Supplier Already Exists" });  // Change the message here
    }

    res.status(200).json({ message: "Supplier name is available." });
  } catch (err) {
    console.error("Error checking supplier name:", err);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.post('/api/check-supplier-field', async (req, res) => {
  try {
    const { field, value } = req.body;

    if (!field || !value) {
      return res.status(400).json({ message: "Field and value are required." });
    }

    let query = {};
    query[field] = value;

    const existingSupplier = await db.collection('suppliers').findOne(query);

    if (existingSupplier) {
      let readableField = {
        name: "Supplier name",
        phone: "Phone number",
        houseStreet: "Address",
      }[field] || "Field";

      return res.status(400).json({ message: `${readableField} already exists.` });
    }

    res.status(200).json({ message: `${field} is available.` });
  } catch (err) {
    console.error("Error checking supplier field:", err);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.put('/api/update-supplier/:id', async (req, res) => {
  try {
    const supplierId = req.params.id;
    const { name, contactPerson, email, region, houseStreet, phone } = req.body;

    if (!supplierId) {
      return res.status(400).json({ message: 'Supplier ID is required.' });
    }

    const updatedSupplier = {
      ...(name && { name }),
      ...(contactPerson && { contactPerson }),
      ...(email && { email }),
      ...(region && { region }),
      ...(houseStreet && { houseStreet }),
      ...(phone && { phone }),
      updatedAt: new Date(),
    };

    const result = await db.collection('suppliers').updateOne(
      { _id: new ObjectId(supplierId) },
      { $set: updatedSupplier }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Supplier not found or no changes made.' });
    }

    res.status(200).json({ message: 'Supplier updated successfully.' });
  } catch (err) {
    console.error('Error updating supplier:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Delete a supplier
app.delete('/api/delete-supplier/:id', async (req, res) => {
  try {
    const supplierId = req.params.id;
    if (!supplierId) {
      return res.status(400).json({ message: "Supplier ID is required." });
    }
    const result = await db.collection('suppliers').deleteOne({ _id: new ObjectId(supplierId) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Supplier not found." });
    }
    res.status(200).json({ message: "Supplier deleted successfully." });
  } catch (err) {
    console.error("Error deleting supplier:", err);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Fetching staff supplier
app.get('/api/staffSuppliers', async (req, res) => {
  try {
    const { staffUsername } = req.query;

    // Ensure staffUsername is provided before querying
    if (!staffUsername) {
      return res.status(400).json({ message: "staffUsername is required" });
    }

    const suppliers = await db.collection('suppliers').find({ staffUsername }).toArray();
    res.status(200).json(suppliers);
  } catch (err) {
    console.error('Error fetching suppliers:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// -----------------END OF SUPPLIER-------------------------

// --------------------DASHBOARD-----------------------------------
app.get('/api/total-user-shipping', async (req, res) => {
  try {
    const userShippingCollection = db.collection('userShipping');
    const totalShipping = await userShippingCollection.countDocuments();
    res.status(200).json({ totalShipping });
  } catch (error) {
    console.error('Error fetching total userShipping:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/total-to-receive', async (req, res) => {
  try {
    const toReceiveCollection = db.collection('toReceive');
    const totalToReceive = await toReceiveCollection.countDocuments();
    res.status(200).json({ totalToReceive });
  } catch (error) {
    console.error('Error fetching total toReceive:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/total-stocks', async (req, res) => {
  try {
    const stocksCollection = db.collection('stocks');

    const totalStocks = await stocksCollection.countDocuments();
    const lowStockCount = await stocksCollection.countDocuments({ quantity: { $lte: 10 } });

    res.status(200).json({ totalStocks, lowStockCount });
  } catch (error) {
    console.error('Error fetching stock counts:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// --------------------END OF DASHBOARD-----------------------------------
// Fetch all userShipping records regardless of staffUsername
app.get('/api/all-shipping', async (req, res) => {
  try {
    const userShipping = await db.collection('userShipping')
      .find() // No staffUsername filter, so this gets all orders
      .toArray();

    if (userShipping.length === 0) {
      return res.status(404).json({ message: "No shipping records found." });
    }

    res.status(200).json(userShipping);
  } catch (error) {
    console.error("Error fetching all shipping details:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.post('/api/move-to-receive', async (req, res) => {
  try {
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ message: "Order ID is required." });

    const userShipping = db.collection('userShipping');
    const toReceive = db.collection('toReceive');

    // Find the order by ID
    const order = await userShipping.findOne({ _id: new ObjectId(orderId) });
    if (!order) return res.status(404).json({ message: "Order not found." });

    // Insert into toReceive
    await toReceive.insertOne(order);

    // Remove from userShipping
    await userShipping.deleteOne({ _id: new ObjectId(orderId) });

    res.status(200).json({ message: "Order moved to toReceive successfully." });
  } catch (error) {
    console.error("Error moving order to toReceive:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Fetch all to receive orders
app.get('/api/all-receiving', async (req, res) => {
  try {
    const toReceive = await db.collection('toReceive')
      .find()
      .toArray();

    if (toReceive.length === 0) {
      return res.status(404).json({ message: "No receiving records found." });
    }

    res.status(200).json(toReceive);
  } catch (error) {
    console.error("Error fetching receiving details:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// ------------------------- ADMIN ----------------------------------------
// API to log in to Admin
app.post('/api/admin', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Find admin in the database
    const user = await db.collection('admin').findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Direct string comparison (NO bcrypt)
    if (password !== user.password) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Generate JWT token
    const token = generateToken(user);

    return res.status(200).json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Error during admin login:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// --------------ADMIN PRODUCT CATEGORY API--------------------------------
// Add a new product maintenance 
// app.post('/api/admin-product-maintenance', async (req, res) => {
//   try {
//     let { category, subCategory, brand, color, sizes } = req.body;

//     // Ensure all fields are arrays
//     category = Array.isArray(category) ? category : [category];
//     subCategory = Array.isArray(subCategory) ? subCategory : [subCategory];
//     brand = Array.isArray(brand) ? brand : [brand];
//     color = Array.isArray(color) ? color : [color];
//     sizes = Array.isArray(sizes) ? sizes : [sizes];

//     const newEntry = { category, subCategory, brand, color, sizes };
//     const result = await productMaintenanceCollection().insertOne(newEntry);
//     res.status(201).json(result);
//   } catch (error) {
//     res.status(500).json({ error: "Failed to add product maintenance data." });
//   }
// });
// Add a new product with productID
app.post('/api/adminadd-product-maintenance', async (req, res) => {
  try {
    let { category, subCategory, brand, color, sizes, productID } = req.body;

    // Generate productID if not provided
    if (!productID) {
      productID = `P-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
    }

    // Ensure all fields are arrays
    category = Array.isArray(category) ? category : [category];
    subCategory = Array.isArray(subCategory) ? subCategory : [subCategory];
    brand = Array.isArray(brand) ? brand : [brand];
    color = Array.isArray(color) ? color : [color];
    sizes = Array.isArray(sizes) ? sizes : [sizes];

    const newEntry = { productID, category, subCategory, brand, color, sizes };

    const result = await productMaintenanceCollection().insertOne(newEntry);

    res.status(201).json({ message: "Product added successfully", data: result });
  } catch (error) {
    console.error("Error adding product maintenance data:", error);
    res.status(500).json({ error: "Failed to add product maintenance data." });
  }
});
// With Unique category
// app.post('/api/adminadd-product-maintenance', async (req, res) => {
//   try {
//     let { category, subCategory, brand, color, sizes, productID } = req.body;

//     // Generate productID if not provided
//     if (!productID) {
//       productID = `P-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
//     }

//     // Ensure category is a string, not an array
//     category = typeof category === 'string' ? category : category.join(", ");
//     subCategory = Array.isArray(subCategory) ? subCategory.join(", ") : subCategory;
//     brand = Array.isArray(brand) ? brand.join(", ") : brand;
//     color = Array.isArray(color) ? color.join(", ") : color;
//     sizes = Array.isArray(sizes) ? sizes.join(", ") : sizes;

//     const newEntry = { productID, category, subCategory, brand, color, sizes };

//     const result = await productMaintenanceCollection().insertOne(newEntry);

//     res.status(201).json({ message: "Product added successfully", data: result });
//   } catch (error) {
//     console.error("Error adding product maintenance data:", error);
//     res.status(500).json({ error: "Failed to add product maintenance data." });
//   }
// });

// Add this route to check if a category already exists
// app.get('/api/check-category', async (req, res) => {
//   try {
//     const { category } = req.query;
//     const existingProduct = await productMaintenanceCollection().findOne({ category });

//     if (existingProduct) {
//       return res.status(200).json({ exists: true });
//     }
//     return res.status(200).json({ exists: false });
//   } catch (error) {
//     console.error("Error checking category:", error);
//     res.status(500).json({ error: "Failed to check category" });
//   }
// });
// Add this route in your server
// app.get('/api/check-category', async (req, res) => {
//   try {
//     const { category, excludeId } = req.query;
//     const query = {
//       category: Array.isArray(category) ? { $in: category } : category,
//     };

//     if (excludeId) {
//       query._id = { $ne: new ObjectId(excludeId) };
//     }

//     const exists = await productMaintenanceCollection().findOne(query);
//     res.json({ exists: !!exists });
//   } catch (error) {
//     console.error("Category check failed:", error);
//     res.status(500).json({ error: "Internal Server Error" });
//   }
// });
app.get('/api/check-category', async (req, res) => {
  try {
    const { category, excludeId } = req.query;

    if (!category) {
      return res.status(400).json({ error: "Category is required" });
    }

    const categoryRegex = new RegExp(`^${category}$`, 'i');

    const matchQuery = {
      $or: [
        { category: categoryRegex }, // If category is a string
        { category: { $elemMatch: { $regex: categoryRegex } } } // If category is an array
      ]
    };

    const foundDoc = await productMaintenanceCollection().findOne(matchQuery);

    if (!foundDoc) {
      return res.json({ exists: false }); // No conflict, category is unique
    }

    if (excludeId && foundDoc._id.toString() === excludeId) {
      return res.json({ exists: false }); // Same document — allow it
    }

    res.json({ exists: true }); // Category exists in another document — duplicate
  } catch (error) {
    console.error("Error checking category:", error);
    res.status(500).json({ error: "Server error" });
  }
});


// Get all product maintenance entries
app.get('/api/product-maintenance', async (req, res) => {
  try {
    const data = await productMaintenanceCollection().find().toArray();
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch product maintenance data." });
  }
});

// Update product maintenance entry Admin
app.put('/api/admin-product-maintenance/:id', async (req, res) => {
  try {
    const { id } = req.params;
    let { category, subCategory, brand, color, sizes } = req.body;

    // Ensure all fields are arrays
    category = Array.isArray(category) ? category : [category];
    subCategory = Array.isArray(subCategory) ? subCategory : [subCategory];
    brand = Array.isArray(brand) ? brand : [brand];
    color = Array.isArray(color) ? color : [color];
    sizes = Array.isArray(sizes) ? sizes : [sizes];

    const updatedEntry = { category, subCategory, brand, color, sizes };
    const result = await productMaintenanceCollection().updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedEntry }
    );
    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({ error: "Failed to update product maintenance data." });
  }
});

// Delete product maintenance
app.delete('/api/admin-product-maintenance/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await productMaintenanceCollection().deleteOne({ _id: new ObjectId(id) });
    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({ error: "Failed to delete product maintenance data." });
  }
});

// ------------------END OF ADMIN PRODUCT CATEGORY API---------------------

// ------------------ADMIN PRODUCT API------------------------------------
// Fetch all products products
app.get('/api/products', async (req, res) => {
  try {
    const products = await db.collection('products').find().toArray();
    res.status(200).json(products);
  } catch (err) {
    console.error('Error fetching products:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// API to add a new product (Modified 4/7)
// app.post('/api/admin-add-product', async (req, res) => {
//   try {
//     const { staffUsername, productName, category, subCategory, brand, gender, size, color, imageUrl } = req.body;

//     if (!productName || !category || !brand || !color || !imageUrl) {
//       return res.status(400).json({ message: 'Missing required fields.' });
//     }

//     const newProduct = {
//       ...(staffUsername && { staffUsername }),
//       productName,
//       category,
//       subCategory: subCategory?.trim() || null,
//       brand,
//       gender: gender?.trim() || null,
//       size: size?.trim() || null,
//       color,
//       imageUrl,
//       createdAt: new Date(),
//     };

//     await db.collection('products').insertOne(newProduct);
//     return res.status(201).json({ message: 'Product added successfully.' });
//   } catch (err) {
//     console.error('Error adding product:', err);
//     return res.status(500).json({ message: 'Internal server error.' });
//   }
// });
app.post('/api/admin-add-product', async (req, res) => {
  try {
    const { staffUsername, productID, productName, category, subCategory, brand, gender, size, color, imageUrl } = req.body;

    if (!productName || !category || !brand || !color || !imageUrl) {
      return res.status(400).json({ message: 'Missing required fields.' });
    }

    const newProduct = {
      ...(staffUsername && { staffUsername }),
      productID,
      productName,
      category,
      subCategory: subCategory?.trim() || null,
      brand,
      gender: gender?.trim() || null,
      size: size?.trim() || null,
      color,
      imageUrl,
      createdAt: new Date(),
    };

    await db.collection('products').insertOne(newProduct);
    return res.status(201).json({ message: 'Product added successfully.' });
  } catch (err) {
    console.error('Error adding product:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// Update product
app.put('/api/admin-update-product/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    const { productName, category, subCategory, gender, size, color, imageUrls } = req.body;

    if (!productId) {
      return res.status(400).json({ message: 'Product ID is required.' });
    }

    const updatedProduct = {
      ...(productName && { productName }),
      ...(category && { category }),
      ...(subCategory && { subCategory }),
      ...(gender && { gender }),
      ...(size && { size }),
      ...(color && { color }),
      ...(imageUrls && { imageUrls }),
      updatedAt: new Date(),
    };

    const result = await db.collection('products').updateOne(
      { _id: new ObjectId(productId) },
      { $set: updatedProduct }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'Product not found or no changes made.' });
    }

    return res.status(200).json({ message: 'Product updated successfully.' });
  } catch (err) {
    console.error('Error updating product:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// Remove products
app.delete('/api/admin-delete-product/:id', async (req, res) => {
  try {
    const productId = req.params.id;

    if (!productId) {
      return res.status(400).json({ message: "Product ID is required." });
    }

    const result = await db.collection('products').deleteOne({ _id: new ObjectId(productId) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Product not found." });
    }

    return res.status(200).json({ message: "Product deleted successfully." });
  } catch (err) {
    console.error("Error deleting product:", err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// ----------------END OF ADMI PRODUCT API----------------------------------

// ------------ADMIN ADD A NEW DELIVERY PRODUCT API-------------------------
// DELIVERY PRODUCT
// app.post('/api/admin-add-delivery', async (req, res) => {
//   try {
//     const { productId, supplierId, supplierPrice, shopPrice, quantity, totalCost, staffUsername } = req.body;

//     if (!productId || !supplierId || !supplierPrice || !shopPrice || !quantity) {
//       return res.status(400).json({ message: "Missing required fields." });
//     }

//     const product = await db.collection('products').findOne({ _id: new ObjectId(productId) });
//     const supplier = await db.collection('suppliers').findOne({ _id: new ObjectId(supplierId) });

//     if (!product || !supplier) {
//       return res.status(404).json({ message: "Product or Supplier not found." });
//     }

//     const randomProductID = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8-char ID like 'A1B2C3D4'

//     // Explicitly set staffUsername to null if it's not provided or is an empty string
//     const validStaffUsername = staffUsername && staffUsername.trim() ? staffUsername : null;

//     const newDelivery = {
//       productID: randomProductID,
//       product: {
//         productName: product.productName,
//         category: product.category,
//         subCategory: product.subCategory,
//         brand: product.brand,
//         gender: product.gender || null,
//         size: product.size || null,
//         color: product.color,
//         imageUrl: product.imageUrl,
//       },
//       supplier: {
//         supplierID: supplier.supplierID,
//         name: supplier.name,
//         contactPerson: supplier.contactPerson,
//         email: supplier.email,
//         region: supplier.region,
//         houseStreet: supplier.houseStreet,
//         phone: supplier.phone,
//       },
//       supplierPrice,
//       shopPrice,
//       quantity,
//       totalCost,
//       staffUsername: validStaffUsername,
//       addedAt: new Date(),
//     };

//     await db.collection('deliveries').insertOne(newDelivery);
//     res.status(201).json({ message: "Delivery added successfully." });
//   } catch (err) {
//     console.error("Error adding delivery:", err);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });
// app.post('/api/admin-add-delivery', async (req, res) => {
//   try {
//     const { productId, supplierId, supplierPrice, shopPrice, quantity, totalCost, staffUsername } = req.body;

//     if (!productId || !supplierId || !supplierPrice || !shopPrice || !quantity) {
//       return res.status(400).json({ message: "Missing required fields." });
//     }

//     const product = await db.collection('products').findOne({ _id: new ObjectId(productId) });
//     const supplier = await db.collection('suppliers').findOne({ _id: new ObjectId(supplierId) });

//     if (!product || !supplier) {
//       return res.status(404).json({ message: "Product or Supplier not found." });
//     }

//     // Explicitly set staffUsername to null if it's not provided or is an empty string
//     const validStaffUsername = staffUsername && staffUsername.trim() ? staffUsername : null;

//     const newDelivery = {
//       productID: product.productID,
//       product: {
//         productName: product.productName,
//         category: product.category,
//         subCategory: product.subCategory,
//         brand: product.brand,
//         gender: product.gender || null,
//         size: product.size || null,
//         color: product.color,
//         imageUrl: product.imageUrl,
//       },
//       supplier: {
//         supplierID: supplier.supplierID,
//         name: supplier.name,
//         contactPerson: supplier.contactPerson,
//         email: supplier.email,
//         region: supplier.region,
//         houseStreet: supplier.houseStreet,
//         phone: supplier.phone,
//       },
//       supplierPrice,
//       shopPrice,
//       quantity,
//       totalCost,
//       staffUsername: validStaffUsername,
//       addedAt: new Date(),
//     };

//     await db.collection('deliveries').insertOne(newDelivery);
//     res.status(201).json({ message: "Delivery added successfully." });
//   } catch (err) {
//     console.error("Error adding delivery:", err);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });
app.post('/api/admin-add-delivery', async (req, res) => {
  try {
    const { deliveryID, productId, supplierId, supplierPrice, shopPrice, quantity, totalCost, staffUsername } = req.body;

    if (!productId || !supplierId || !supplierPrice || !shopPrice || !quantity) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    const product = await db.collection('products').findOne({ _id: new ObjectId(productId) });
    const supplier = await db.collection('suppliers').findOne({ _id: new ObjectId(supplierId) });

    if (!product || !supplier) {
      return res.status(404).json({ message: "Product or Supplier not found." });
    }

    // Explicitly set staffUsername to null if it's not provided or is an empty string
    const validStaffUsername = staffUsername && staffUsername.trim() ? staffUsername : null;

    const newDelivery = {
      deliveryID: deliveryID,
      productID: product.productID,
      product: {
        productName: product.productName,
        category: product.category,
        subCategory: product.subCategory,
        brand: product.brand,
        gender: product.sex || null,
        size: product.size || null,
        color: product.color,
        imageUrl: product.imageUrls,
      },
      supplier: {
        supplierID: supplier.supplierID,
        name: supplier.name,
        contactPerson: supplier.contactPerson,
        email: supplier.email,
        region: supplier.region,
        houseStreet: supplier.houseStreet,
        phone: supplier.phone,
      },
      supplierPrice,
      shopPrice,
      quantity,
      totalCost,
      staffUsername: validStaffUsername,
      addedAt: new Date(),
    };

    await db.collection('deliveries').insertOne(newDelivery);
    res.status(201).json({ message: "Delivery added successfully." });
  } catch (err) {
    console.error("Error adding delivery:", err);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Restocks to deliver
app.post('/api/admin-restocks', async (req, res) => {
  try {
    const { stockId, supplierId, supplierPrice, shopPrice, quantity } = req.body;

    if (!stockId || !supplierId || !supplierPrice || !shopPrice || !quantity) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    // Find stock details
    const stock = await db.collection('stocks').findOne({ _id: new ObjectId(stockId) });
    const supplier = await db.collection('suppliers').findOne({ _id: new ObjectId(supplierId) });

    if (!stock || !supplier) {
      return res.status(404).json({ message: "Stock or Supplier not found." });
    }

    const newDelivery = {
      deliveryID: stock.deliveryID,
      productID: stock.productID,
      product: stock.product,
      supplier: supplier,
      supplierPrice,
      shopPrice,
      quantity,
      totalCost: supplierPrice * quantity,
      addedAt: new Date(),
    };

    // Insert into deliveries
    await db.collection('deliveries').insertOne(newDelivery);

    res.status(201).json({ message: "Restock added to deliveries." });
  } catch (err) {
    console.error('Error restocking product:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ADD STOCKS + DELIVERY HISTORY
// app.post('/api/admin-set-as-delivered/:id', async (req, res) => {
//   try {
//     const deliveryId = req.params.id;

//     // Find the delivery by ID
//     const delivery = await db.collection('deliveries').findOne({ _id: new ObjectId(deliveryId) });

//     if (!delivery) {
//       return res.status(404).json({ message: "Delivery not found" });
//     }

//     const stocksCollection = db.collection('stocks');

//     // Check if stock with this productID already exists
//     const existingStock = await stocksCollection.findOne({ productID: delivery.productID });

//     if (existingStock) {
//       // Update supplierPrice, shopPrice, and increment quantity
//       await stocksCollection.updateOne(
//         { productID: delivery.productID },
//         {
//           $set: {
//             supplierPrice: delivery.supplierPrice,
//             shopPrice: delivery.shopPrice,
//           },
//           $inc: {
//             quantity: delivery.quantity
//           }
//         }
//       );
//     } else {
//       // Insert new stock record
//       const newStock = {
//         productID: delivery.productID,
//         product: delivery.product,
//         supplier: delivery.supplier,
//         supplierPrice: delivery.supplierPrice,
//         shopPrice: delivery.shopPrice,
//         quantity: delivery.quantity,
//         totalCost: delivery.totalCost,
//         staffUsername: delivery.staffUsername,
//         deliveredAt: new Date()
//       };

//       await stocksCollection.insertOne(newStock);
//     }

//     // Always insert into delivery_history
//     await db.collection('delivery_history').insertOne({
//       ...delivery,
//       deliveredAt: new Date()
//     });

//     // Remove from deliveries
//     await db.collection('deliveries').deleteOne({ _id: new ObjectId(deliveryId) });

//     res.status(200).json({ message: "Set as delivered. Stock updated and delivery history recorded." });
//   } catch (err) {
//     console.error("Error setting as delivered:", err);
//     res.status(500).json({ message: "Internal server error" });
//   }
// });

// app.post('/api/admin-set-as-delivered/:id', async (req, res) => {
//   try {
//     const deliveryId = req.params.id;

//     // Find the delivery by ID
//     const delivery = await db.collection('deliveries').findOne({ _id: new ObjectId(deliveryId) });

//     if (!delivery) {
//       return res.status(404).json({ message: "Delivery not found" });
//     }

//     const existingStock = await db.collection('stocks').findOne({ productID: delivery.productID });

//     if (existingStock) {
//       // Update existing stock entry
//       await db.collection('stocks').updateOne(
//         { productID: delivery.productID },
//         {
//           $set: {
//             supplier: delivery.supplier,
//             supplierPrice: delivery.supplierPrice,
//             shopPrice: delivery.shopPrice,
//             totalCost: delivery.totalCost,
//           },
//           $inc: { quantity: delivery.quantity }, // Increment the quantity
//         }
//       );
//       res.status(200).json({ message: "Stock updated successfully" });
//     } else {
//       // Insert new stock entry
//       await db.collection('stocks').insertOne({
//         productID: delivery.productID,
//         product: delivery.product,
//         supplier: delivery.supplier,
//         supplierPrice: delivery.supplierPrice,
//         shopPrice: delivery.shopPrice,
//         quantity: delivery.quantity,
//         totalCost: delivery.totalCost,
//         staffUsername: delivery.staffUsername,
//         addedAt: new Date(),
//       });
//       res.status(200).json({ message: "Set as delivered and moved to stock" });
//     }

//     // Remove from deliveries collection
//     await db.collection('deliveries').deleteOne({ _id: new ObjectId(deliveryId) });

//   } catch (err) {
//     console.error("Error setting as delivered:", err);
//     res.status(500).json({ message: "Internal server error" });
//   }
// });
app.post('/api/set-as-delivered/:id', async (req, res) => {
  try {
    const deliveryId = req.params.id;
    const { staffUsername } = req.body;

    if (!staffUsername) {
      return res.status(400).json({ message: "Staff username is required." });
    }

    // Find the delivery from the deliveries collection
    const delivery = await db.collection('deliveries').findOne({ _id: new ObjectId(deliveryId) });

    if (!delivery) {
      return res.status(404).json({ message: "Delivery not found." });
    }

    const stocksCollection = db.collection('stocks');

    // Check if the delivery has already been processed into stocks
    const existingStock = await stocksCollection.findOne({ deliveryID: delivery.deliveryID });

    if (existingStock) {
      // If it exists, update the stock
      await stocksCollection.updateOne(
        { deliveryID: delivery.deliveryID },
        {
          $set: {
            supplierPrice: delivery.supplierPrice,
            shopPrice: delivery.shopPrice,
          },
          $inc: {
            quantity: delivery.quantity, // increment the stock quantity
          },
        }
      );
    } else {
      // If it doesn't exist, insert a new stock record
      await stocksCollection.insertOne({
        deliveryID: delivery.deliveryID,
        productID: delivery.productID,
        product: delivery.product,
        supplier: delivery.supplier,
        supplierPrice: delivery.supplierPrice,
        shopPrice: delivery.shopPrice,
        quantity: delivery.quantity,
        totalCost: delivery.totalCost,
        staffUsername: delivery.staffUsername,
        deliveredAt: new Date(),
      });
    }

    // Insert into delivery history
    await db.collection('delivery_history').insertOne({
      ...delivery,
      deliveredAt: new Date(),
    });

    // Remove the delivery from the deliveries collection
    await db.collection('deliveries').deleteOne({ _id: new ObjectId(deliveryId) });

    // Log the audit trail
    const staffInfo = await db.collection('staff').findOne({ username: staffUsername });
    await db.collection('auditTrailLogs').insertOne({
      username: staffUsername,
      role: 'Staff',
      action: 'Staff Set a Delivered Product',
      affectedId: delivery.productID,
      timestamp: new Date(),
      accountInfo: staffInfo || {},
    });

    return res.status(200).json({ message: "Set as delivered, added to stock, and logged to history." });
  } catch (err) {
    console.error('Error setting as delivered:', err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// app.post('/api/admin-set-as-delivered/:id', async (req, res) => {
//   try {
//     const deliveryId = req.params.id;

//     // Find the delivery by ID
//     const delivery = await db.collection('deliveries').findOne({ _id: new ObjectId(deliveryId) });

//     if (!delivery) {
//       return res.status(404).json({ message: "Delivery not found" });
//     }

//     const stocksCollection = db.collection('stocks');

//      // Check if the delivery has already been processed into stocks
//      const existingStock = await stocksCollection.findOne({ deliveryID: delivery.deliveryID });

//      if (existingStock) {
//        // If it exists, update the stock
//        await stocksCollection.updateOne(
//          { deliveryID: delivery.deliveryID },
//          {
//            $set: {
//              supplierPrice: delivery.supplierPrice,
//              shopPrice: delivery.shopPrice,
//            },
//            $inc: {
//              quantity: delivery.quantity, // increment the stock quantity
//            },
//          }
//        );
//      } else {
//        // If it doesn't exist, insert a new stock record
//        await stocksCollection.insertOne({
//          deliveryID: delivery.deliveryID,
//          productID: delivery.productID,
//          product: delivery.product,
//          supplier: delivery.supplier,
//          supplierPrice: delivery.supplierPrice,
//          shopPrice: delivery.shopPrice,
//          quantity: delivery.quantity,
//          totalCost: delivery.totalCost,
//          staffUsername: delivery.staffUsername,
//          deliveredAt: new Date(),
//        });
//        return res.status(200).json({ message: "Set as delivered, added to stock, and logged to history." });
//      }

//     // Remove from deliveries collection
//     await db.collection('deliveries').deleteOne({ _id: new ObjectId(deliveryId) });

//   } catch (err) {
//     console.error("Error setting as delivered:", err);
//     res.status(500).json({ message: "Internal server error" });
//   }
// });
app.post('/api/admin-set-as-delivered/:id', async (req, res) => {
  try {
    const deliveryId = req.params.id;
    const delivery = await db.collection('deliveries').findOne({ _id: new ObjectId(deliveryId) });

    if (!delivery) {
      return res.status(404).json({ message: "Delivery not found" });
    }

    const stocksCollection = db.collection('stocks');
    const existingStock = await stocksCollection.findOne({ deliveryID: delivery.deliveryID });

    if (existingStock) {
      await stocksCollection.updateOne(
        { deliveryID: delivery.deliveryID },
        {
          $set: {
            supplierPrice: delivery.supplierPrice,
            shopPrice: delivery.shopPrice,
          },
          $inc: {
            quantity: delivery.quantity,
          },
        }
      );
    } else {
      await stocksCollection.insertOne({
        deliveryID: delivery.deliveryID,
        productID: delivery.productID,
        product: delivery.product,
        supplier: delivery.supplier,
        supplierPrice: delivery.supplierPrice,
        shopPrice: delivery.shopPrice,
        quantity: delivery.quantity,
        totalCost: delivery.totalCost,
        staffUsername: delivery.staffUsername,
        deliveredAt: new Date(),
      });
    }

    // Insert into delivery history
    await db.collection('delivery_history').insertOne({
      ...delivery,
      deliveredAt: new Date(),
    });

    // ✅ Move this outside the if...else so it runs in both cases
    await db.collection('deliveries').deleteOne({ _id: new ObjectId(deliveryId) });

    return res.status(200).json({ message: "Set as delivered, added to stock, and logged to history." });

  } catch (err) {
    console.error("Error setting as delivered:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Backend: Set all deliveries as delivered
app.post('/api/set-all-delivered', async (req, res) => {
  try {
    const { staffUsername } = req.body;

    const deliveries = db.collection("deliveries");
    const stocks = db.collection("stocks");

    const allDeliveries = await deliveries.find().toArray();

    for (const delivery of allDeliveries) {
      const existingStock = await stocks.findOne({ deliveryID: delivery.deliveryID });

      if (existingStock) {
        await stocks.updateOne(
          { deliveryID: delivery.deliveryID },
          {
            $set: {
              supplierPrice: delivery.supplierPrice,
              shopPrice: delivery.shopPrice,
            },
            $inc: {
              quantity: delivery.quantity,
            },
          }
        );
      } else {
        await stocks.insertOne({
          deliveryID: delivery.deliveryID,
          productID: delivery.productID,
          product: delivery.product,
          supplier: delivery.supplier,
          supplierPrice: delivery.supplierPrice,
          shopPrice: delivery.shopPrice,
          quantity: delivery.quantity,
          totalCost: delivery.totalCost,
          staffUsername: staffUsername || null,
          deliveredAt: new Date(),
        });
      }

      // Insert into delivery history
      await db.collection('delivery_history').insertOne({
        ...delivery,
        deliveredAt: new Date(),
      });

      await deliveries.deleteOne({ _id: delivery._id });
    }

    res.status(200).json({ message: 'All deliveries marked as delivered and moved to stock.' });
  } catch (err) {
    console.error('Error setting all as delivered:', err);
    res.status(500).json({ error: 'Failed to set all as delivered.' });
  }
});

// ------------END OF ADMIN ADD A NEW DELIVERY PRODUCT API-------------------------

// ---------------------AUDIT TRAIL LOGS---------------
// Get audit logs by role
app.get('/api/audit-logs', async (req, res) => {
  const role = req.query.role;
  try {
    const filter = role ? { role } : {};
    const logs = await db.collection('auditTrailLogs').find(filter).sort({ timestamp: -1 }).toArray();
    res.json(logs);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching audit logs' });
  }
});
// -----------END OF AUDIT TRAIL LOGS-------------------

// -------------------ADMIN VAT API----------------------------
// Get VAT
app.get('/api/admin/vat', async (req, res) => {
  try {
    const vatCollection = db.collection('vat');
    const vat = await vatCollection.findOne({});
    res.status(200).json(vat || {});
  } catch (err) {
    console.error('Error fetching VAT:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Add or update VAT (only one document allowed)
app.post('/api/admin/vat', async (req, res) => {
  try {
    const { value } = req.body;
    if (typeof value !== 'number') {
      return res.status(400).json({ message: 'VAT value must be a number' });
    }

    const vatCollection = db.collection('vat');
    const existing = await vatCollection.findOne({});

    if (existing) {
      return res.status(400).json({ message: 'VAT already exists. You can only update it.' });
    }

    await vatCollection.insertOne({ value, createdAt: new Date() });
    res.status(201).json({ message: 'VAT added successfully' });
  } catch (err) {
    console.error('Error adding VAT:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update VAT
app.put('/api/admin/vat', async (req, res) => {
  try {
    const { value } = req.body;
    if (typeof value !== 'number') {
      return res.status(400).json({ message: 'VAT value must be a number' });
    }

    const vatCollection = db.collection('vat');
    const result = await vatCollection.updateOne({}, { $set: { value } });

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'VAT not found' });
    }

    res.status(200).json({ message: 'VAT updated successfully' });
  } catch (err) {
    console.error('Error updating VAT:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// ----------------END OF ADMIN VAT API--------------------------

// -------------------SUPPLIER------------------------------
// Admin ADDING new supplier
// app.post('/api/adminAdd-supplier', async (req, res) => {
//   try {
//     const { name, contactPerson, email, region, houseStreet, phone } = req.body;

//     if (!name || !contactPerson || !email || !region || !houseStreet || !phone) {
//       return res.status(400).json({ message: "All fields are required." });
//     }

//     // Check if the supplier name already exists in the database
//     const existingSupplier = await db.collection('suppliers').findOne({ name });
//     if (existingSupplier) {
//       return res.status(400).json({ message: "Supplier name must be unique." });
//     }

//     const newSupplier = {
//       name,
//       contactPerson,
//       email,
//       region,
//       houseStreet,
//       phone,
//       createdAt: new Date(),
//     };

//     await db.collection('suppliers').insertOne(newSupplier);
//     return res.status(201).json({ message: "Supplier added successfully." });
//   } catch (err) {
//     console.error("Error adding supplier:", err);
//     return res.status(500).json({ message: "Internal server error." });
//   }
// });
// ADMIN Adding Supplier with supplierID
app.post('/api/adminAdd-supplier', async (req, res) => {
  try {
    const { name, contactPerson, email, region, houseStreet, phone } = req.body;

    if (!name || !contactPerson || !email || !region || !houseStreet || !phone) {
      return res.status(400).json({ message: "All fields are required." });
    }

    // Check if the supplier name already exists
    const existingSupplier = await db.collection('suppliers').findOne({ name });
    if (existingSupplier) {
      return res.status(400).json({ message: "Supplier name must be unique." });
    }

    // Generate unique supplierID
    const supplierID = `SUP-${Date.now()}`;

    const newSupplier = {
      supplierID,
      name,
      contactPerson,
      email,
      region,
      houseStreet,
      phone,
      createdAt: new Date(),
    };

    await db.collection('suppliers').insertOne(newSupplier);
    return res.status(201).json({ message: "Supplier added successfully." });
  } catch (err) {
    console.error("Error adding supplier:", err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// Fetch all suppliers
app.get('/api/suppliers', async (req, res) => {
  try {
    const suppliers = await db.collection('suppliers').find().toArray();
    res.status(200).json(suppliers);
  } catch (err) {
    console.error('Error fetching suppliers:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Fetch deliveries with product and supplier data
app.get('/api/deliveries', async (req, res) => {
  try {
    const deliveries = await db.collection('deliveries')
      .find({})
      .sort({ addedAt: -1 })
      .toArray();

    res.status(200).json(deliveries);
  } catch (err) {
    console.error('Error fetching deliveries:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// -------------------END OF SUPPLIER------------------------------

// admin mark as received
// app.post('/api/admin-mark-received/:orderId', async (req, res) => {
//   try {
//     const { orderId } = req.params;
//     const { orderReceivedDate } = req.body;

//     const toReceive = db.collection('toReceive');
//     const orderReceived = db.collection('orderReceived');

//     const order = await toReceive.findOne({ _id: new ObjectId(orderId) });

//     if (!order) {
//       return res.status(404).json({ message: "Order not found in toReceive." });
//     }

//     // Attach orderReceivedDate to order
//     order.orderReceivedDate = orderReceivedDate || new Date().toISOString().split('T')[0];

//     await orderReceived.insertMany(order);
//     await toReceive.deleteMany({ _id: new ObjectId(orderId) });

//     res.status(200).json({ message: "Order marked as received." });
//   } catch (error) {
//     console.error("Error marking order as received:", error);
//     res.status(500).json({ message: "Internal server error." });
//   }
// });

// Admin mark as orders received
app.post('/api/admin-mark-received', async (req, res) => {
  try {
    const { orderId, orderReceivedDate } = req.body;

    if (!orderId) {
      return res.status(400).json({ message: "Order ID is required." });
    }

    const toReceive = db.collection('toReceive');
    const orderReceived = db.collection('orderReceived');

    // Step 1: Find the order by _id to get the userOrderID
    const singleOrder = await toReceive.findOne({ _id: new ObjectId(orderId) });
    if (!singleOrder) return res.status(404).json({ message: "Order not found." });

    const { userOrderID } = singleOrder;

    // Step 2: Find all orders with the same userOrderID
    const relatedOrders = await toReceive.find({ userOrderID }).toArray();

    // Step 3: Set the received date for each order
    const dateToUse = orderReceivedDate || new Date().toISOString().split('T')[0];
    const ordersWithDate = relatedOrders.map(order => ({
      ...order,
      orderReceivedDate: dateToUse
    }));

    // Step 4: Insert them into orderReceived
    await orderReceived.insertMany(ordersWithDate);

    // Step 5: Delete them from toReceive
    await toReceive.deleteMany({ userOrderID });

    res.status(200).json({ message: "Order group marked as received." });
  } catch (error) {
    console.error("Error marking order as received:", error.message, error.stack);
    res.status(500).json({ message: "Internal server error." });
  }
});

// admin cancel to receive orders
app.post('/api/admin-cancel-order/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;
    const { canceledReason } = req.body;

    const orderReceived = db.collection('toReceive');
    const canceledOrders = db.collection('canceledOrders');

    const order = await orderReceived.findOne({ _id: new ObjectId(orderId) });

    if (!order) {
      return res.status(404).json({ message: "Order not found in orderReceived." });
    }

    // Add canceledReason and canceledDate
    order.canceledReason = canceledReason;
    order.canceledDate = new Date().toISOString().split('T')[0];

    await canceledOrders.insertOne(order);
    await orderReceived.deleteOne({ _id: new ObjectId(orderId) });

    res.status(200).json({ message: "Order canceled successfully." });
  } catch (error) {
    console.error("Error canceling order:", error);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Updated set-as-delivered endpoint to handle productID check
// app.post('/api/set-as-delivered/:id', async (req, res) => {
//   try {
//     const deliveryId = req.params.id;

//     // Find the delivery by ID
//     const delivery = await db.collection('deliveries').findOne({ _id: new ObjectId(deliveryId) });

//     if (!delivery) {
//       return res.status(404).json({ message: "Delivery not found" });
//     }

//     const existingStock = await db.collection('stocks').findOne({ productID: delivery.productID });

//     if (existingStock) {
//       // Update existing stock entry
//       await db.collection('stocks').updateOne(
//         { productID: delivery.productID },
//         {
//           $set: {
//             supplier: delivery.supplier,
//             supplierPrice: delivery.supplierPrice,
//             shopPrice: delivery.shopPrice,
//             totalCost: delivery.totalCost,
//           },
//           $inc: { quantity: delivery.quantity }, // Increment the quantity
//         }
//       );
//       res.status(200).json({ message: "Stock updated successfully" });
//     } else {
//       // Insert new stock entry
//       await db.collection('stocks').insertOne({
//         productID: delivery.productID,
//         product: delivery.product,
//         supplier: delivery.supplier,
//         supplierPrice: delivery.supplierPrice,
//         shopPrice: delivery.shopPrice,
//         quantity: delivery.quantity,
//         totalCost: delivery.totalCost,
//         staffUsername: delivery.staffUsername || null,
//         addedAt: new Date(),
//       });
//       res.status(200).json({ message: "Set as delivered and moved to stock" });
//     }

//     // Remove from deliveries collection
//     await db.collection('deliveries').deleteOne({ _id: new ObjectId(deliveryId) });

//   } catch (err) {
//     console.error("Error setting as delivered:", err);
//     res.status(500).json({ message: "Internal server error" });
//   }
// });

// Delivered history
app.get('/api/delivery-history', async (req, res) => {
  try {
    const deliveredHistory = await db.collection('delivery_history')
      .find({})
      .sort({ addedAt: -1 })
      .toArray();

    res.status(200).json(deliveredHistory);
  } catch (err) {
    console.error('Failed to fetch delivery history:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Fetch all stocks
app.get('/api/stocks', async (req, res) => {
  try {
    const stocks = await db.collection('stocks').find().sort({ addedAt: -1 }).toArray();
    res.status(200).json(stocks);
  } catch (err) {
    console.error("Error fetching stocks:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// User fetch with 0 quantity indicator
app.get('/api/userStocks', async (req, res) => {
  try {
    const stocks = await db.collection('stocks')
      .find({ quantity: { $gt: 0 } }) // Only fetch stocks with quantity > 0
      .sort({ addedAt: -1 })
      .toArray();

    res.status(200).json(stocks);
  } catch (err) {
    console.error("Error fetching stocks:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// API USER Search stocks
app.get('/api/search-userStocks', async (req, res) => {
  try {
    const searchQuery = req.query.search || '';
    const regex = new RegExp(searchQuery, 'i'); // Case-insensitive regex

    const stocks = await db.collection('stocks')
      .find({
        quantity: { $gt: 0 },
        'product.productName': { $regex: regex }
      })
      .sort({ addedAt: -1 })
      .toArray();

    res.status(200).json(stocks);
  } catch (err) {
    console.error("Error fetching stocks:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Update stock by ID
app.put('/api/update-stock/:id', async (req, res) => {
  const { id } = req.params;
  const { product, quantity, shopPrice } = req.body;

  try {
    const result = await db.collection('stocks').updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          product,
          quantity,
          shopPrice,
          updatedAt: new Date(),
        },
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: "Stock not found or already up to date" });
    }

    res.status(200).json({ message: "Stock updated successfully" });
  } catch (error) {
    console.error("Error updating stock:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Delete a stock product by ID
app.delete('/api/delete-stock/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.collection('stocks').deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.status(200).json({ message: "Product deleted successfully" });
  } catch (err) {
    console.error("Error deleting product:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get('/api/user-list', async (req, res) => {
  try {
    // Fetch all users
    const users = await db.collection('users').find().toArray();

    // Fetch account info for each user
    const userListWithInfo = await Promise.all(
      users.map(async (user) => {
        const accountInfo = await db.collection('account_info').findOne({ username: user.username });
        return {
          username: user.username,
          password: user.password, // You may decide to exclude or hash this before sending
          ...accountInfo, // Merge account info with the user data
        };
      })
    );

    res.status(200).json(userListWithInfo);
  } catch (err) {
    console.error('Error fetching user list:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// EDIT user ADMIN
// app.put('/api/user/:username', async (req, res) => {
//   try {
//     const { username } = req.params;
//     const { recipientName, phoneNumber, region, houseStreet } = req.body;

//     const updatedUser = await db.collection('account_info').updateOne(
//       { username },
//       { $set: { recipientName, phoneNumber, region, houseStreet } }
//     );

//     if (updatedUser.modifiedCount > 0) {
//       res.status(200).json({ message: 'User updated successfully' });
//     } else {
//       res.status(404).json({ message: 'User not found or no changes made' });
//     }
//   } catch (err) {
//     res.status(500).json({ message: 'Internal server error' });
//   }
// });

// EDIT user ADMIN - Update account_info and users (password)
app.put('/api/user/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const { recipientName, phoneNumber, region, houseStreet, password } = req.body;

    const dbUpdate1 = await db.collection('account_info').updateOne(
      { username },
      { $set: { recipientName, phoneNumber, region, houseStreet } }
    );

    const dbUpdate2 = password
      ? await db.collection('users').updateOne(
        { username },
        { $set: { password } }
      )
      : { modifiedCount: 0 };

    if (dbUpdate1.modifiedCount > 0 || dbUpdate2.modifiedCount > 0) {
      res.status(200).json({ message: 'User updated successfully' });
    } else {
      res.status(404).json({ message: 'User not found or no changes made' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// DELETE user ADMIN
app.delete('/api/user/:username', async (req, res) => {
  try {
    const { username } = req.params;

    // Delete from both collections
    const userResult = await db.collection('users').deleteOne({ username });
    const accountInfoResult = await db.collection('account_info').deleteOne({ username });

    if (userResult.deletedCount > 0 || accountInfoResult.deletedCount > 0) {
      res.status(200).json({ message: 'User deleted successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Fetch all staff users
app.get('/api/staff-list', async (req, res) => {
  try {
    const staffList = await db.collection('staff').find({}, { projection: { _id: 0, password: 1, username: 1, staffFullname: 1, contactPerson: 1, phoneNumber: 1, email: 1, region: 1, houseStreet: 1 } }).toArray();

    if (!staffList.length) {
      return res.status(404).json({ message: 'No staff found.' });
    }

    res.status(200).json(staffList);
  } catch (err) {
    console.error('Error fetching staff list:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// DELETE staff
app.delete('/api/staff/:username', async (req, res) => {
  try {
    const { username } = req.params;

    const deleteResult = await db.collection('staff').deleteOne({ username });

    if (deleteResult.deletedCount > 0) {
      res.status(200).json({ message: 'Staff deleted successfully' });
    } else {
      res.status(404).json({ message: 'Staff not found' });
    }
  } catch (err) {
    console.error('Error deleting staff:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Example protected route
app.get('/api/protected', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'Access granted.', user: req.user });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));