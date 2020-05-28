const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomBytes } = require("crypto");
const { promisify } = require("util");
const { hasPermission } = require("../utils");
const { transport, makeANiceMail } = require("../mail");
const stripe = require("../stripe");

const Mutations = {
  async createItem(parent, args, ctx, info) {
    // TODO: Check if the They are logged in
    if (!ctx.request.userId) {
      throw new Error("You must be logged in to do that!");
    }
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          // This is how we create relationship between item and the user
          user: { connect: { id: ctx.request.userId } },
          ...args,
        },
      },
      info
    );

    return item;
  },
  updateItem(parent, args, ctx, info) {
    // first take a copy of the updates
    const updates = { ...args };
    // remove the ID from the copy
    delete updates.id;
    // Run the update method
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: { id: args.id },
      },
      info
    );
  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    // 1. Find item
    const item = await ctx.db.query.item(
      { where },
      `{id
     title
    user{
      id
    }
    }`
    );
    // 2. Check if they own or have permission to delete the item
    const ownsItem = item.user.id === ctx.request.userId;
    const hasPermission = ctx.request.user.permission.some((permission) =>
      ["ADMIN", "DELETEITEM"].includes(permission)
    );

    if (!ownsItem && !hasPermission) {
      throw new Error("You are not allowed to Delete this item");
    }
    // 3. Delete
    return ctx.db.mutation.deleteItem({ where }, info);
  },
  async signup(parent, args, ctx, info) {
    // lowerCase the email
    args.email = args.email.toLowerCase();
    // hash password
    const password = await bcrypt.hash(args.password, 9);

    const user = await ctx.db.mutation.createUser(
      {
        data: { ...args, password, permission: { set: ["USER"] } },
      },
      info
    );

    // create jwt token for user
    const token = await jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // Set the token as a cookie on the response
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365,
    });
    // finally we return the user object
    return user;
  },
  async signin(parent, { email, password }, ctx, info) {
    // 1. confirm email exists in the db
    email = email.toLowerCase();
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`No user found with email: ${email}`);
    }
    // 2. Confirm password is correct
    const valid = bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error("Invalid password");
    }
    // 3. Generate jwt for the user
    const token = await jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // Set the token as a cookie on the response
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365,
    });
    // 5. return user
    return user;
  },
  signout(parent, args, ctx, info) {
    ctx.response.clearCookie("token");
    return { message: "Goodbye!" };
  },
  async requestReset(parent, args, ctx, info) {
    const email = args.email.toLowerCase();
    // 1. confirm the user is valid
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`No user found with email: ${email}`);
    }
    // 2. generate a unique token
    const promisifiedRandomBytes = promisify(randomBytes);
    const resetToken = (await promisifiedRandomBytes(20)).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000; //1 hour from now
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email },
      data: { resetToken, resetTokenExpiry },
    });
    // 3. send the token to the user's mail
    const mailRes = await transport.sendMail({
      from: "sick-fit@mail.com",
      to: user.email,
      subject: "Your password reset link",
      html: makeANiceMail(
        `Click on the link to reset your password, the link expires in one(1) hour
        \n\n
         <a href="${process.env.FRONTEND_URL}/reset?resetToken=${
          updatedUser.resetToken
        }">
         Reset Password</a>
        `,
        updatedUser.name
      ),
    });

    // 4. return message
    return { message: "Success" };
  },
  async resetPassword(parent, args, ctx, info) {
    // 1. Check if password match
    if (args.password !== args.confirmPassword) {
      throw new Error("The passwords provided do not match");
    }
    // 2. Check if it is a legit reset token
    // 3. Check if the reset token is expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000,
      },
    });
    if (!user) {
      throw new Error("Either the reset password token is expired or invalid");
    }

    // 4. Hash the new password
    const hashedPassword = await bcrypt.hash(args.password, 9);
    // 5. Save the new password to the user and remove old reset token field
    const updatedUser = await ctx.db.mutation.updateUser(
      {
        where: {
          email: user.email,
        },
        data: {
          password: hashedPassword,
          resetTokenExpiry: null,
          resetToken: null,
        },
      },
      info
    );
    // 6. Generate a new jwt
    const authToken = await jwt.sign(
      { userId: updatedUser.id },
      process.env.APP_SECRET
    );
    // 7. Set the token to new jwt token
    ctx.response.cookie("token", authToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365,
    });
    // 8. return user
    return updatedUser;
    // 9. Done
  },
  async updatePermission(parent, args, ctx, info) {
    // 1. Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error("You must be logged in to continue");
    }
    // 2. Query the current user
    // 3. check if they have permissions to do this
    hasPermission(ctx.request.user, ["ADMIN", "PERMISSIONUPDATE"]);
    // 4. Update the permissions
    return ctx.db.mutation.updateUser(
      {
        data: {
          permission: { set: args.permission },
        },
        where: {
          id: args.userId,
        },
      },
      info
    );
  },
  async addToCart(parent, args, ctx, info) {
    // 1. Check if user is logged in
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error("You must be signed in to add to cart");
    }
    // 2. Query users current cart
    const [existingCartItem] = await ctx.db.query.cartItems(
      {
        where: {
          user: {
            id: userId,
          },
          item: { id: args.id },
        },
      },
      info
    );
    // 3. Check if that item is already in the cart then increase its quantity
    if (existingCartItem) {
      return ctx.db.mutation.updateCartItem({
        where: { id: existingCartItem.id },
        data: { quantity: existingCartItem.quantity + 1 },
      });
    }
    // 4. If its not create a fresh cartItem for the user
    return ctx.db.mutation.createCartItem(
      {
        data: {
          user: {
            connect: { id: userId },
          },
          item: {
            connect: { id: args.id },
          },
        },
      },
      info
    );
  },
  async removeFromCart(parent, { id }, ctx, info) {
    const { userId } = ctx.request;
    // 1. find the cart item
    const cartItem = await ctx.db.query.cartItem(
      { where: { id } },
      `{id, user {id}}`
    );
    // 1.5 Confirm cartitem exist
    if (!cartItem) throw new Error("No cart item found!");
    // 2. confirm they own that cartitem
    if (cartItem.user.id !== userId) throw new Error("Cheating uuuh!!");
    // 3. delete item
    return ctx.db.mutation.deleteCartItem({ where: { id } }, info);
  },
  async createOrder(parent, { token }, ctx, info) {
    // 1. query user object and make sure they are signed in
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error("You must be signed in to carry out this operation");
    }
    const user = await ctx.db.query.user(
      { where: { id: userId } },
      `{
        id 
        name 
        email
        cart {
          id
          quantity
          item {
            id
            price
            title
            description
            image
            largeImage
          }
        }
        
      }`
    );
    // 2. recalculate the total for the price
    const total = user.cart.reduce(
      (tally, cartItem) => tally + cartItem.item.price * cartItem.quantity,
      0
    );
    // 3. Create the stripe charge
    const charge = await stripe.charges.create({
      amount: total * 100,
      currency: "NGN",
      source: token,
    });
    // 4. Convert the Cart Items to OrderItems
    const orderItems = user.cart.map((cartItem) => {
      const { title, price, image, largeImage, description } = cartItem.item;
      return {
        user: { connect: { id: userId } },
        title,
        price,
        image,
        largeImage,
        description,
        quantity: cartItem.quantity,
      };
    });
    // 5. Create the order
    const order = await ctx.db.mutation.createOrder({
      data: {
        charge: charge.id,
        total: charge.amount,
        items: { create: orderItems },
        user: { connect: { id: userId } },
      },
    });
    // 6. Clean up - clear the user's Cart, delete cartItems
    const cartItemIds = user.cart.map((cartItem) => cartItem.id);
    await ctx.db.mutation.deleteManyCartItems({
      where: { id_in: cartItemIds },
    });
    // 7. Return the order to the client
    return order;
  },
};

module.exports = Mutations;
