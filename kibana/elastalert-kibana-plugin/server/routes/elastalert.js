export default function(server, options) {
  const baseUri = `http${options.serverSsl ? 's' : ''}://${options.serverHost}:${options.serverPort}`;

  // Route every request to the ElastAlert API
  const handler = {
    proxy: {
      mapUri: request => {
        return { uri: `${baseUri}/${request.params.path || ''}` };
      }
    }
  };

  ['GET', 'POST', 'DELETE'].forEach(method => {
     server.route({
       path: '/api/elastalert/{path*}',
       method,
       handler,
       config:
         method === 'GET'
           ? undefined
           : {
               validate: { payload: null },
               payload: { parse: false },
             },
      });
  });
}
