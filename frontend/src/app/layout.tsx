import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import { ClerkProvider } from '@clerk/nextjs';
import { dark } from '@clerk/themes';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'BREACH.AI - Enterprise Security Scanner',
  description: 'Autonomous penetration testing powered by AI',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ClerkProvider
      appearance={{
        baseTheme: dark,
        variables: {
          colorPrimary: '#ef4444',
          colorBackground: '#0a0a0a',
        },
      }}
    >
      <html lang="en" className="dark">
        <body className={inter.className}>{children}</body>
      </html>
    </ClerkProvider>
  );
}
