# Real-world form corpus

Each page here is a small copy of a form pattern that the extension has to
handle on real sites, such as framework markup, odd visibility tricks, shadow
DOM, iframes or redrawn forms. `form_corpus.spec.cjs` loads every page with the
real extension in Chromium. It checks which in-page buttons each marked field
gets, and that each button is drawn over its own field.

Mark a field with `data-expect`. The value is a space-separated list of the
buttons it should get, or an empty string for none:

| Token | Button |
|---|---|
| `login` | Choose saved credentials (key) |
| `totp` | Choose one-time code |
| `generate` | Generate a strong password |
| `card` | Choose payment card |
| `identity` | Choose identity |

A button over an unmarked field, or one that isn't over any field, fails the
test. Buttons parked off the page are ignored, since nobody can see them. Unmarked fields that get no button are ignored.

A field the extension gets wrong today can be marked with
`data-known-issue="<what goes wrong>"`. It is then reported as a known issue
instead of failing, and the test fails once the issue is fixed so the marker
gets removed.

A page that builds its form in steps can put `data-corpus-pending` on any
element and remove it when the page is ready.

To add a regression: save the smallest page that shows the problem (no real
names, emails or tokens), mark its fields, and run
`npx playwright test form_corpus`.
