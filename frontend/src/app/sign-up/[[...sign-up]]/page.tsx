import { SignUp } from "@clerk/nextjs";

export default function SignUpPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#f5f5f5]">
      <SignUp
        appearance={{
          elements: {
            rootBox: "mx-auto",
            card: "shadow-none border border-[#e5e5e5]",
            headerTitle: "font-semibold",
            headerSubtitle: "text-[#737373]",
            formButtonPrimary: "bg-black hover:bg-black/90",
          },
        }}
      />
    </div>
  );
}
