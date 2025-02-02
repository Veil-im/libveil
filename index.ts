/*
 * This is a simple server to run the tests bundles in the browser.
 */

const server = Bun.serve({
  port: 3000,
  async fetch(req) {
    const file = Bun.file('out/browser.test.js');
    const template = `
        <!DOCTYPE html>
        <html>
            <body>
                <script>
                    ${await file.text()}
                </script>
            </body>
        </html>
        `;
    return new Response(template, {
      headers: {
        'Content-Type': 'text/html',
      },
    });
  },
});

console.log(`Server is running on http://localhost:${server.port}`);
