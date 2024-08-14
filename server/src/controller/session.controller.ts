import { CookieOptions, Request, Response } from "express";
import config from "config";
import {
  createSession,
  findSessions,
  updateSession,
} from "../service/session.service";
import {
  findAndUpdateUser,
  getGoogleOAuthTokens,
  getGoogleUser,
  validatePassword,
} from "../service/user.service";
import { signJwt } from "../utils/jwt.utils";
import { string } from "zod";
import { access } from "fs/promises";
import log from "../utils/logger";
import jwt from "jsonwebtoken";

const accessTokenCookieOptions: CookieOptions = {
  maxAge: 900000, //15 mins
  httpOnly: true,
  domain: "localhost",
  path: "/",
  sameSite: "lax", // lax or strict
  secure: false,
};

const refreshTokenCookieOptions: CookieOptions = {
  ...accessTokenCookieOptions,
  maxAge: 3.154e10, // 1 year
};

export async function createUserSessionHandler(req: Request, res: Response) {
  // Validate the user's password
  const user = await validatePassword(req.body);

  if (!user) {
    return res.status(401).send("Invalid email or password");
  }

  // create a session
  const session = await createSession(user._id, req.get("user-agent") || "");

  // create an access token

  const accessToken = signJwt(
    { ...user, session: session._id },
    { expiresIn: config.get("accessTokenTtl") } // 15 minutes
  );

  // create a refresh token
  const refreshToken = signJwt(
    { ...user, session: session._id },
    { expiresIn: config.get("refreshTokenTtl") } // 15 minutes
  );

  // return access & refresh tokens

  res.cookie("accessToken", accessToken, accessTokenCookieOptions);

  res.cookie("refreshToken", refreshToken, refreshTokenCookieOptions);

  return res.send({ accessToken, refreshToken });
}

export async function getUserSessionsHandler(req: Request, res: Response) {
  const userId = res.locals.user._id;

  const sessions = await findSessions({ user: userId, valid: true });

  return res.send(sessions);
}

export async function deleteSessionHandler(req: Request, res: Response) {
  const sessionId = res.locals.user.session;

  await updateSession({ _id: sessionId }, { valid: false });

  return res.send({
    accessToken: null,
    refreshToken: null,
  });
}

export async function googleOauthHandler(req: Request, res: Response) {
  try {
    // get the code from qs (query string)
    const code = req.query.code;

    // get the id and access token with code
    const { id_token, access_token } = await getGoogleOAuthTokens({
      code,
    } as any);

    // get user with tokens
    // const googleUser = jwt.decode(id_token);
    const googleUser = await getGoogleUser({ id_token, access_token });
    if (!googleUser.verified_email) {
      res.status(403).send("Google user is not verified");
    }
    // upsert the user
    const user = await findAndUpdateUser(
      {
        email: googleUser.email,
      },
      {
        email: googleUser.email,
        name: googleUser.name,
        picture: googleUser.picture,
      },
      {
        upsert: true,
        new: true,
      }
    );

    // create s session
    const session = await createSession(user._id, req.get("user-agent") || "");

    // create an access token

    const accessToken = signJwt(
      { ...user.toJSON(), session: session._id },
      { expiresIn: config.get("accessTokenTtl") } // 15 minutes
    );

    // create a refresh token
    const refreshToken = signJwt(
      { ...user.toJSON(), session: session._id },
      { expiresIn: config.get("refreshTokenTtl") } // 1 year
    );

    // set cookies

    res.cookie("accessToken", accessToken, accessTokenCookieOptions);

    res.cookie("refreshToken", refreshToken, refreshTokenCookieOptions);

    // redirect back to client
    res.redirect(config.get("origin"));
  } catch (err: any) {
    log.error(err, "Failed to authorize google user");
    return res.redirect(`${process.env.ORIGIN}/oauth${err}`);
  }
}
