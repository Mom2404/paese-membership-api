import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

const jwks = jwksClient({
  jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, function (err, key) {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!process.env.AUTH0_DOMAIN || !process.env.AUTH0_AUDIENCE) {
    return res.status(500).json({
      error: "Server misconfigured",
      missing: {
        AUTH0_DOMAIN: !process.env.AUTH0_DOMAIN,
        AUTH0_AUDIENCE: !process.env.AUTH0_AUDIENCE,
      },
    });
  }

  try {
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({ active: false });
    }

    const token = auth.slice("Bearer ".length);

    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(
        token,
        getKey,
        {
          audience: process.env.AUTH0_AUDIENCE,
          issuer: `https://${process.env.AUTH0_DOMAIN}/`,
          algorithms: ["RS256"],
        },
        (err, payload) => (err ? reject(err) : resolve(payload))
      );
    });

    return res.status(200).json({
      active: true,
      tier: "member",
      user: decoded.sub,
    });
  } catch {
    return res.status(401).json({ active: false, error: "invalid_token" });
  }
}
