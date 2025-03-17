
import {Request,Response, NextFunction } from "express";
import { auth } from "express-oauth2-jwt-bearer";
import jwt from "jsonwebtoken"
import User from '../models/user';

declare global{
  namespace Express {
    interface Request{
      userId: string;
      auth0Id: string;
    }
  }
}

export const jwtCheck = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL:process.env.AUTH0_ISSUER_BASE_URL,
  tokenSigningAlg: "RS256",
});

export const jwtParse = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const { authorization } = req.headers;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    res.sendStatus(401);
    return;
  }

  const token = authorization.split(" ")[1];

  try {
    const decoded = jwt.decode(token) as jwt.JwtPayload;

    if (!decoded || !decoded.sub) {
      res.sendStatus(401);
      return;
    }

    const auth0Id = decoded.sub;

    User.findOne({ auth0Id })
      .then((user) => {
        if (!user) {
          res.sendStatus(401);
          return;
        }

        req.auth0Id = auth0Id;
        req.userId = user._id.toString();
        next(); // ✅ Call next() when successful
      })
      .catch((error) => {
        console.error("JWT Parse Error:", error);
        res.sendStatus(500);
      });
  } catch (error) {
    console.error("JWT Parse Error:", error);
    res.sendStatus(401);
  }
};