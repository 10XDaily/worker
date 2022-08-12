import { Router } from 'itty-router'

// Create a new router
const router = Router()

/*
Our index route, a simple hello world.
*/
router.get("/", () => {
  console.log("testing logs");
  return new Response("10X Your Day!")
})

/*
Experimenting with Content shortlinks and Referral IDs
Default Referral = 10X Daily
Content Referral = Content Creator (e.g. blog post publishers)
Traffic Referral = Traffic Source (e.g. 10x daily users)
*/
const default_ref_id = '123' // default Referral ID

// Content ID slugs
const content = {
  '1': {
    'content_ref_id': default_ref_id // default Referral ID for this content
  },
  '2': {
    'content_ref_id': '456' // custom Referral ID for this content creator
  }
}

// Redirect to landingpage URL... for now everything will redirect here.
const redirect_to = 'https://10x.day'

/*
Extract the short Content ID from URL then redirect to a landing page

Try visit /1 and see the response for Default Referral ID
Try visit /2 and see the response for Content Referral ID
Try visit /2?ref=789 and see the response for Traffic Referral ID
*/
router.get("/:slug", ({ params, query }) => {
  let content_id = params.slug;
  let content_data = content[content_id];
  
  if(!content_data) {
      return new Response('Content ID not found.', {
      status: 404,
    });
  } else {
    let content_ref = content_data.content_ref_id;
    let traffic_ref = '';
    
    // Get traffic Referral ID from query parameters
    traffic_ref = query.ref || query.ref_id || '';
    let has_traffic_ref = traffic_ref ? true : false; 
    
    let referral = content_ref;
    
    // Traffic referred by someone else e.g. worker.10X.day/2?ref=789
    if(has_traffic_ref) {
      referral = traffic_ref;
    }
    
    let referral_query_string = `ref_id=${referral}&`;
        
    let link = `${redirect_to}?${referral_query_string}traffic_ref=${traffic_ref}&utm_content=${content_id}`;
    
    return new Response(null, {
      headers: { Location: link },
      status: 302,
    });
  };
})


/*
This is the last route we define, it will match anything that hasn't hit a route we've defined
above, therefore it's useful as a 404 (and avoids us hitting worker exceptions, so make sure to include it!).

Visit any page that doesn't exist (e.g. /foobar) to see it in action.
*/
router.all("*", () => new Response("404, not found!", { status: 404 }))

/*
This snippet ties our worker to the router we deifned above, all incoming requests
are passed to the router where your routes are called and the response is sent.
*/
addEventListener('fetch', (e) => {
  e.respondWith(router.handle(e.request))
})
