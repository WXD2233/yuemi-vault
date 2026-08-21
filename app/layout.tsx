import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL("http://localhost:3000"),
  title: "钥密 · 安全密码管理器",
  description:
    "生成高强度密码、加密保存账号，并通过主密码与新设备邮箱验证保护你的密码库。",
  openGraph: {
    title: "钥密 · 安全密码管理器",
    description: "主密码保护、邮箱二次验证与可信设备管理。",
    images: ["/og.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "钥密 · 安全密码管理器",
    description: "主密码保护、邮箱二次验证与可信设备管理。",
    images: ["/og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh-CN" data-theme="dark" suppressHydrationWarning>
      <head>
        <script src="/theme-init.js" defer />
      </head>
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        {children}
      </body>
    </html>
  );
}
