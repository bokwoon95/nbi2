## General
- DO NOT make changes to files unless directly requested by me. Show me the proposed changes before carrying it out.
- If I ask you a question, DO NOT make changes on my behalf. ANSWER the question instead.
- DO NOT create single use functions which merely serve as descriptive containers of code. DO inline the code as much as possible and sprinkle comments if too cryptic. NO utility functions!
- DO NOT create intermediate variables which merely serve as descriptive containers of a value. DO inline literals and expressions as much as possible and sprinkle comments if too cryptic. NO useless variables!
- DO use the minimum number of HTML elements where possible. No div soup!
- HTML, CSS and JS use two space indentation.
- When achieving effects by CSS, use the bare minimum rules (i.e. no rules to make it look pretty) unless otherwise specified.
- For every CSS rule added, justify why it exists with a comment otherwise remove it. Use the bare minimum CSS rules!

## Go

go run -tags dev ./notebrew

All routing is defined in serve\_http.go. The router is consumed in notebrew/main.go.

## HTML

All HTML pages are located in embed/, and all include base.html and the templates within. Refer to how the `templateMap` global variable in the nbi2 package is initialized in the init() function.

## CSS
@tailwindcss/cli --input ./notebrew.css --output ./static/styles.css --watch=always

The source CSS file is notebrew.css, but the actual CSS file in effect is static/styles.css.

BasecoatUI components are used heavily. You can find its source in node\_modules.

## JavaScript
esbuild notebrew.ts --bundle --outdir=static --watch=forever

You can find JavaScript source files in node\_modules.
