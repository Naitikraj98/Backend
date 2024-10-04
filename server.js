const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
app.use(cors());
const port = process.env.PORT || 5000;


mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection failed:', err.message));


const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now },
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model('User', userSchema);



const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  status: { type: String, enum: ['completed', 'incomplete'], default: 'incomplete' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  completedAt: Date,
});

const Task = mongoose.model('Task', taskSchema);


const auth = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};


const admin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admins only.' });
  }
  next();
};


app.post('/api/users/signup', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    const newUser = new User({ username, email, password });
    await newUser.save();

    const token = jwt.sign({ id: newUser._id, role: newUser.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
    console.error('Error during signup:', error);
  }
});


app.post('/api/users/login', async (req, res) => {
    const { usernameOrEmail, password } = req.body;
  
    try {
      
      const user = await User.findOne({
        $or: [{ email: usernameOrEmail }, { username: usernameOrEmail }],
      });
      
      if (!user) return res.status(400).json({ message: 'Invalid credentials' });
  
      
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
  
      
      const token = jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
  
      res.status(200).json({ token,username: user.username, message: 'Login successful' });
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  });
  


app.post('/api/tasks', auth, async (req, res) => {
  const { title, description } = req.body;

  try {
    const newTask = new Task({
      title,
      description,
      createdBy: req.user.id,
    });
    await newTask.save();
    res.status(201).json(newTask);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});


app.get('/api/tasks', auth, async (req, res) => {
  try {
    const tasks = await Task.find({ createdBy: req.user.id }).populate('assignedTo', 'username');
    res.status(200).json(tasks);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});


app.put('/api/tasks/:id', auth, async (req, res) => {
  const { id } = req.params;
  const { title, description, status, assignedTo } = req.body;

  try {
    const task = await Task.findById(id);
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }

    if (req.user.role === 'admin' || task.createdBy.toString() === req.user.id) {
      task.title = title;
      task.description = description;
      task.status = status;
      task.assignedTo = assignedTo;
      await task.save();

      return res.status(200).json(task);
    }

    res.status(403).json({ message: 'You are not authorized to edit this task' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});


app.put('/api/tasks/:id/assign', auth, admin, async (req, res) => {
  const { id } = req.params;
  const { userId } = req.body;

  try {
    const task = await Task.findById(id);
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    task.assignedTo = userId;
    await task.save();
    res.status(200).json(task);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});


app.delete('/api/tasks/:id', auth, async (req, res) => {
  const { id } = req.params;
  try {
    const deletedTask = await Task.findByIdAndDelete(id);
    if (!deletedTask) return res.status(404).json({ message: 'Task not found' });
    res.status(200).json({ message: 'Task deleted successfully', task: deletedTask });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});


app.put('/api/tasks/:id/status', auth, async (req, res) => {
    const { id } = req.params; 
    const { status } = req.body; 

    if (!['completed', 'incomplete'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status value' });
    }

    try {
        const task = await Task.findById(id);
        if (!task) {
            return res.status(404).json({ message: 'Task not found' });
        }

        if (req.user.role === 'admin' || task.createdBy.toString() === req.user.id) {
            task.status = status;

            if (status === 'completed') {
                task.completedAt = new Date(); 
            } else {
                task.completedAt = null;  
            }

            await task.save();
            return res.status(200).json({ message: 'Task status updated', task });
        }

        res.status(403).json({ message: 'You are not authorized to update the status of this task' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

  

app.listen(port, () => console.log(`Server running on port ${port}`));
