import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import cors from "cors";
import helmet from "helmet";
import pino from "pino";
import pinoHttp from "pino-http";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";

dotenv.config();

const {
  PORT = "3000",
  NODE_ENV = "development",
  CORS_ORIGIN = "",
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  JWT_SECRET,
  ADMIN_DISCORD_IDS = "",
} = process.env;

if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI || !JWT_SECRET) {
  throw new Error("Missing required env vars: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI, JWT_SECRET");
}

const isProd = NODE_ENV === "production";

const log = pino({
  level: isProd ? "info" : "debug",
  transport: isProd
    ? undefined
    : {
        target: "pino-pretty",
        options: {
          colorize: true,
          translateTime: "SYS:standard",
        },
      },
});

const prisma = new PrismaClient();
const app = express();

const ROLES = ["ADMIN", "MOD", "USER"] as const;
type Role = (typeof ROLES)[number];

type AuthUser = {
  id: string;
  role: Role;
  discordId: string;
};

type AuthRequest = express.Request & {
  user?: AuthUser;
};

type DiscordUser = {
  id: string;
  username?: string;
  global_name?: string | null;
  avatar?: string | null;
  email?: string | null;
};

const adminDiscordIds = new Set(
  ADMIN_DISCORD_IDS.split(",").map((id) => id.trim()).filter(Boolean)
);

const createOAuthUrl = (state: string) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify email",
    state,
  });

  return `https://discord.com/api/oauth2/authorize?${params.toString()}`;
};

const getState = () => crypto.randomBytes(16).toString("hex");

const getBearerToken = (req: express.Request) => {
  const auth = req.header("authorization") ?? "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match?.[1];
};

const isRole = (value: unknown): value is Role => {
  return typeof value === "string" && ROLES.includes(value as Role);
};

const getUserRole = (role: unknown): Role => {
  return isRole(role) ? role : "USER";
};

const signToken = (user: AuthUser) => {
  return jwt.sign(
    {
      sub: user.id,
      role: user.role,
      discordId: user.discordId,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
};

const requireAuth = (req: AuthRequest, res: express.Response, next: express.NextFunction) => {
  const token = getBearerToken(req);

  if (!token) {
    return res.status(401).json({ error: "Missing Bearer token" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload;

    req.user = {
      id: String(payload.sub),
      role: getUserRole(payload.role),
      discordId: String(payload.discordId),
    };

    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

const requireRole = (...roles: Role[]) => {
  return (req: AuthRequest, res: express.Response, next: express.NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: "Unauthenticated" });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }

    next();
  };
};

const asyncHandler =
  (
    fn: (
      req: AuthRequest,
      res: express.Response,
      next: express.NextFunction
    ) => Promise<unknown>
  ) =>
  (req: AuthRequest, res: express.Response, next: express.NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };

const exchangeCodeForToken = async (code: string) => {
  const response = await fetch("https://discord.com/api/v10/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: DISCORD_REDIRECT_URI,
    }).toString(),
  });

  return response;
};

const fetchDiscordUser = async (accessToken: string) => {
  const response = await fetch("https://discord.com/api/v10/users/@me", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  return response;
};

app.use(helmet());
app.use(
  cors({
    origin: CORS_ORIGIN ? CORS_ORIGIN.split(",").map((origin) => origin.trim()) : true,
    credentials: true,
  })
);
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(pinoHttp({ logger: log }));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    env: NODE_ENV,
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

app.get("/auth/discord/login", (_req, res) => {
  const state = getState();

  res.cookie("oauth_state", state, {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd,
  });

  res.redirect(createOAuthUrl(state));
});

app.get("/auth/discord/url", (_req, res) => {
  const state = getState();

  res.json({
    url: createOAuthUrl(state),
    state,
  });
});

app.get(
  "/auth/discord/callback",
  asyncHandler(async (req, res) => {
    const code = String(req.query.code ?? "");
    const state = String(req.query.state ?? "");
    const cookieState = String(req.cookies.oauth_state ?? "");

    if (!code || !state) {
      return res.status(400).json({ error: "Missing code/state" });
    }

    if (!cookieState || state !== cookieState) {
      return res.status(400).json({ error: "Bad oauth state" });
    }

    const tokenResponse = await exchangeCodeForToken(code);

    if (!tokenResponse.ok) {
      const details = await tokenResponse.text();
      req.log.warn({ details }, "Token exchange failed");
      return res.status(400).json({ error: "Token exchange failed", details });
    }

    const tokenData = (await tokenResponse.json()) as { access_token: string };
    const accessToken = tokenData.access_token;

    const userResponse = await fetchDiscordUser(accessToken);

    if (!userResponse.ok) {
      const details = await userResponse.text();
      req.log.warn({ details }, "Fetching Discord user failed");
      return res.status(400).json({ error: "Fetching Discord user failed", details });
    }

    const discordUser = (await userResponse.json()) as DiscordUser;
    const discordId = String(discordUser.id);
    const username = String(discordUser.username ?? "unknown");
    const globalName = discordUser.global_name ? String(discordUser.global_name) : null;
    const avatar = discordUser.avatar ? String(discordUser.avatar) : null;
    const email = discordUser.email ? String(discordUser.email) : null;

    const existingUser = await prisma.user.findUnique({
      where: { discordId },
    });

    const existingRole = getUserRole(existingUser?.role);
    const role: Role = adminDiscordIds.has(discordId) ? "ADMIN" : existingRole;

    const user = await prisma.user.upsert({
      where: { discordId },
      create: {
        discordId,
        username,
        globalName,
        avatar,
        email,
        role,
      },
      update: {
        username,
        globalName,
        avatar,
        email,
        role,
      },
    });

    if (user.disabled) {
      return res.status(403).json({ error: "Account disabled" });
    }

    const token = signToken({
      id: user.id,
      role,
      discordId: user.discordId,
    });

    res.clearCookie("oauth_state");

    res.json({
      token,
      user: {
        id: user.id,
        discordId: user.discordId,
        role: user.role,
        reactiveLink: user.reactiveLink,
        disabled: user.disabled,
      },
    });
  })
);

app.get(
  "/me",
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.user!.id;

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }

    res.json({
      id: user.id,
      discordId: user.discordId,
      username: user.username,
      globalName: user.globalName,
      avatar: user.avatar,
      email: user.email,
      role: user.role,
      reactiveLink: user.reactiveLink,
      disabled: user.disabled,
    });
  })
);

app.get(
  "/admin/users",
  requireAuth,
  requireRole("ADMIN"),
  asyncHandler(async (_req, res) => {
    const users = await prisma.user.findMany({
      orderBy: { createdAt: "desc" },
    });

    res.json(users);
  })
);

app.get(
  "/admin/users/:id",
  requireAuth,
  requireRole("ADMIN"),
  asyncHandler(async (req, res) => {
    const user = await prisma.user.findUnique({
      where: { id: req.params.id },
    });

    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }

    res.json(user);
  })
);

app.post(
  "/admin/users",
  requireAuth,
  requireRole("ADMIN"),
  asyncHandler(async (req, res) => {
    const schema = z.object({
      discordId: z.string().min(1),
      username: z.string().min(1).default("unknown"),
      role: z.enum(ROLES).optional(),
      reactiveLink: z.string().url().optional(),
      disabled: z.boolean().optional(),
    });

    const body = schema.parse(req.body);

    const user = await prisma.user.create({
      data: {
        discordId: body.discordId,
        username: body.username,
        role: body.role ?? "USER",
        reactiveLink: body.reactiveLink,
        disabled: body.disabled ?? false,
      },
    });

    res.status(201).json(user);
  })
);

app.patch(
  "/admin/users/:id",
  requireAuth,
  requireRole("ADMIN"),
  asyncHandler(async (req, res) => {
    const schema = z.object({
      role: z.enum(ROLES).optional(),
      reactiveLink: z.string().url().nullable().optional(),
      disabled: z.boolean().optional(),
    });

    const body = schema.parse(req.body);

    if (req.user!.id === req.params.id && body.role && body.role !== "ADMIN") {
      return res.status(400).json({ error: "Admins cannot demote themselves" });
    }

    const user = await prisma.user.update({
      where: { id: req.params.id },
      data: {
        ...(body.role !== undefined && { role: body.role }),
        ...(body.disabled !== undefined && { disabled: body.disabled }),
        ...(body.reactiveLink !== undefined && { reactiveLink: body.reactiveLink }),
      },
    });

    res.json(user);
  })
);

app.put(
  "/admin/users/:id/reactive-link",
  requireAuth,
  requireRole("ADMIN"),
  asyncHandler(async (req, res) => {
    const schema = z.object({
      reactiveLink: z.string().url().nullable(),
    });

    const body = schema.parse(req.body);

    const user = await prisma.user.update({
      where: { id: req.params.id },
      data: { reactiveLink: body.reactiveLink },
    });

    res.json(user);
  })
);

app.delete(
  "/admin/users/:id",
  requireAuth,
  requireRole("ADMIN"),
  asyncHandler(async (req, res) => {
    const user = await prisma.user.update({
      where: { id: req.params.id },
      data: { disabled: true },
    });

    res.json({
      ok: true,
      id: user.id,
      disabled: user.disabled,
    });
  })
);

app.use((err: any, req: any, res: any, _next: express.NextFunction) => {
  req.log.error({ err }, "Unhandled error");

  const status = typeof err?.status === "number" ? err.status : 500;

  res.status(status).json({
    error: "Server error",
  });
});

app.listen(Number(PORT), () => {
  log.info(`API listening on http://localhost:${PORT}`);
});