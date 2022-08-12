## worker

Using the [`itty-router`](https://github.com/kwhitley/itty-router) package to add routing to Cloudflare Workers.

index.js is the content of the Workers script.

Using Github Actions to deploy automatically on every commit. 

Worker will be used to manually (via HTML page) or automatically (via Workers CRON) trigger the creation of daily emails to the [`https://10X.DAY`](https://10X.DAY) email subscribers.

Email service provider is [`GetResponse`](https://www.getresponse.com?a=FpXX9nknVn).

Database no-code backend is [`Xano`](https://xano.io/kkdub7op).
