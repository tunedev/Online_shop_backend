const { forwardTo } = require("prisma-binding");
const { hasPermission } = require("../utils");

const Query = {
  items: forwardTo("db"),
  item: forwardTo("db"),
  itemsConnection: forwardTo("db"),
  me(parent, args, ctx, info) {
    // Check if there is a current user ID
    if (!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user(
      {
        where: { id: ctx.request.userId },
      },
      info
    );
  },
  async users(parent, args, ctx, info) {
    // 1. check if user is logged in
    if (!ctx.request.userId) {
      throw new Error("You need to login!");
    }
    // 2. check if user has permission to query all users
    hasPermission(ctx.request.user, ["ADMIN", "PERMISSIONUPDATE"]);
    // 3. return all users once the above checks are passed
    return ctx.db.query.users({}, info);
  },
  async order(parent, { id }, ctx, info) {
    // 1. Confirm the user is logged in
    if (!ctx.request.userId) {
      throw new Error("You are not signed in!");
    }
    // 2. Query the current order
    const order = await ctx.db.query.order(
      {
        where: { id },
      },
      info
    );
    // 3. Check if they have the permissions to see this order
    const ownsOrder = order.user.id === ctx.request.userId;
    const hasPermissionToSeeOrder = ctx.request.user.permission.includes(
      "ADMIN"
    );
    if (!ownsOrder || !hasPermissionToSeeOrder) {
      throw new Error("You do not have permissions to view this :(");
    }
    // 4. Return the order
    return order;
  },
  async orders(parent, args, ctx, info) {
    // 1. confirm user is signed in
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error("You must be signed in.");
    }
    return ctx.db.query.orders({ where: { user: { id: userId } } }, info);
  },
};

module.exports = Query;
