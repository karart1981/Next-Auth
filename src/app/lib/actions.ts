"use server";

import { InputUser, PartialUser } from "./types";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import { addUser, getUserByLogin } from "./api";
import { redirect } from "next/navigation";

export const handleSignup = async (prev: unknown, data: FormData) => {
  const name = data.get("name") as string | null;
  const surname = data.get("surname") as string | null;
  const login = data.get("login") as string | null;
  const password = data.get("password") as string | null;

  if (!name || !surname || !login || !password) {
    return {
      message: "Please fill all the fields",
    };
  }

  const passwordRegex =
    /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{6,}$/;
  if (!passwordRegex.test(password)) {
    return {
      message:
        "Password must be at least 6 characters long and include uppercase and lowercase letters, a number, and a symbol.",
    };
  }

  const user: PartialUser = {
    id: nanoid(),
    name: name,
    surname: surname,
    login: login,
    password: password,
  };

  const existingUser = getUserByLogin(user.login);
  if (existingUser) {
    return {
      message: "Login already exists. Please choose a different login.",
    };
  }

  if (user.password) {
    user.password = await bcrypt.hash(user.password, 10);
  }
  const result = addUser(user);
  console.log(result);

  redirect("/login");
};

export const handleLogin = async (prev: unknown, data: FormData) => {
  const login = data.get("login") as string | null;
  const password = data.get("password") as string | null;

  if (!login || !password) {
    return {
      message: "Please fill all the fields",
    };
  }

  const user = getUserByLogin(login);
  if (!user) {
    return {
      message: "No user found with this login.",
    };
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return {
      message: "Incorrect password.",
    };
  }

  redirect("/profile");
};
