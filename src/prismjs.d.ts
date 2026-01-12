declare module "prismjs" {
  namespace Prism {
    type Grammar = Record<string, unknown>;
  }
  const Prism: {
    highlight: (code: string, grammar: Prism.Grammar, language: string) => string;
    languages: Record<string, Prism.Grammar>;
    Grammar: Prism.Grammar;
  };
  export default Prism;
}

declare module "prismjs/components/*" {
  // Side-effect only imports for language support
}
