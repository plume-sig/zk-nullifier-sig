/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // Add the headers function to set the required headers
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "Cross-Origin-Embedder-Policy",
            value: "require-corp",
          },
          {
            key: "Cross-Origin-Opener-Policy",
            value: "same-origin",
          },
        ],
      },
    ];
  },

  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.module.rules.push({
        test: /\.worker\.ts$/,
        loader: "worker-loader",
        options: {
          publicPath: "/_next/static/workers/",
        },
      });
    }

    return config;
  },
};

export default nextConfig;
