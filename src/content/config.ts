// src/content/config.ts

import { defineCollection, z } from 'astro:content';

const writeupsCollection = defineCollection({
  type: 'content',
  schema: z.object({
    // --- REQUIRED PROPERTIES (USED IN YOUR CARD/LINKING) ---
    title: z.string(),
    description: z.string(),
    
    // The tags must be an array of strings, and it's REQUIRED for filtering/cards
    tags: z.array(z.string()), 
    
    // --- OPTIONAL PROPERTIES (Used in the full article page) ---
    author: z.string().optional(), // Make optional if it might be missing
    // Use z.string().or(z.date()) to allow either the string format "2024-03-22" or a Date object
    date: z.string().or(z.date()).optional(), 
    
    heroImage: z.string().optional(),
    
    // The layout field is no longer in your MD file, so it should be optional 
    // or removed completely. Since it's causing conflicts, let's remove it 
    // to keep the schema clean. If your MDX files use a different layout, 
    // we can re-add it as optional.
    // layout: z.string().optional(), // REMOVE THIS LINE
  }),
});

export const collections = {
  'writeups': writeupsCollection,
};