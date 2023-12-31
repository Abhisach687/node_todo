import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
const app = express();
app.use(express.json());

const users = [
  {
    id: 1,
    username: "user1",
    password: bcrypt.hashSync("password1", 8),
  },
  {
    id: 2,
    username: "user2",
    password: bcrypt.hashSync("password2", 8),
  },
];

let refreshTokens: { [key: string]: string } = {};

app.post("/signup", (req, res) => {
  const { username, password } = req.body;

  // Check if the username already exists
  const userExists = users.some((user) => user.username === username);
  if (userExists) {
    return res.status(400).json({ message: "Username already exists" });
  }

  // Create a new user
  const newUser = {
    id: users.length + 1,
    username,
    password: bcrypt.hashSync(password, 8),
  };

  // Add the new user to the users array
  users.push(newUser);

  // Respond with the new user (without the password)
  res.status(201).json({ id: newUser.id, username: newUser.username });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  const token = jwt.sign({ id: user.id }, "secret", { expiresIn: "1h" });
  const refreshToken = jwt.sign({ id: user.id }, "secret");

  refreshTokens[refreshToken] = token;

  res.json({ token, refreshToken });
});

app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken || !refreshTokens[refreshToken]) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }

  const user = users.find((u) => u.id === Number(refreshTokens[refreshToken]));
  if (!user) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }

  const token = jwt.sign({ id: user.id }, "secret", { expiresIn: "1h" });

  res.json({ token });
});

interface Todo {
  id: number;
  title: string;
  completed: boolean;
  userId: number;
}

const todos: Todo[] = [];

app.get("/todos", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, "secret");
    const userId = (decoded as { id: number }).id;

    const userTodos = todos.filter((todo) => todo.userId === userId);

    res.json(userTodos);
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

app.get("/todos/:id", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, "secret");
    const userId = (decoded as { id: number }).id;

    const todoId = Number(req.params.id);

    const todo = todos.find(
      (todo) => todo.id === todoId && todo.userId === userId
    );

    if (!todo) {
      return res.status(404).json({ message: "Todo not found" });
    }

    res.json(todo);
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

app.post("/todos", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, "secret");
    const userId = (decoded as { id: number }).id;

    const { title } = req.body;

    const newTodo = {
      id: todos.length + 1,
      title,
      completed: false,
      userId,
    };

    todos.push(newTodo);

    res.json(newTodo);
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

app.put("/todos/:id", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, "secret");
    const userId = (decoded as { id: number }).id;

    const todoId = Number(req.params.id);
    const { title, completed } = req.body;

    const todoIndex = todos.findIndex(
      (todo) => todo.id === todoId && todo.userId === userId
    );

    if (todoIndex === -1) {
      return res.status(404).json({ message: "Todo not found" });
    }

    todos[todoIndex] = {
      ...todos[todoIndex],
      title: title || todos[todoIndex].title,
      completed:
        completed !== undefined ? completed : todos[todoIndex].completed,
    };

    res.json(todos[todoIndex]);
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

app.delete("/todos/:id", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, "secret");
    const userId = (decoded as { id: number }).id;

    const todoId = Number(req.params.id);

    const todoIndex = todos.findIndex(
      (todo) => todo.id === todoId && todo.userId === userId
    );

    if (todoIndex === -1) {
      return res.status(404).json({ message: "Todo not found" });
    }

    const deletedTodo = todos.splice(todoIndex, 1)[0];

    res.json(deletedTodo);
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
