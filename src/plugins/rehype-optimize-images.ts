type HastNode = {
  type?: string;
  tagName?: string;
  properties?: Record<string, unknown>;
  children?: HastNode[];
};

function walk(node: HastNode | undefined) {
  if (!node || typeof node !== "object") return;

  if (node.type === "element" && node.tagName === "img") {
    const properties = node.properties ?? {};
    if (!properties.loading) properties.loading = "lazy";
    if (!properties.decoding) properties.decoding = "async";
    node.properties = properties;
  }

  for (const child of node.children ?? []) {
    walk(child);
  }
}

export function rehypeOptimizeImages() {
  return (tree: HastNode) => {
    walk(tree);
  };
}
