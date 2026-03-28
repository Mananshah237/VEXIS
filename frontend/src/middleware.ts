export { default } from "next-auth/middleware";

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/scan/:path*",
    "/reports/:path*",
    "/settings/:path*",
  ],
};
