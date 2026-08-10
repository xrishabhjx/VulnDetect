/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Disable standalone output for local Windows development because Next.js
  // tries to create symlinks during build, and that can fail with EPERM here.
  output: undefined,
};

export default nextConfig;
