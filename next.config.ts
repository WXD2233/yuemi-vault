import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emit a self-contained production bundle so the runtime image does not
  // need the source tree or build-only dependencies.
  output: "standalone",
};

export default nextConfig;
