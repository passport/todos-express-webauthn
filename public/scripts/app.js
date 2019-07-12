window.onload = function() {
  console.log('loaded...');
  
  document.getElementById('register').addEventListener('click', function(e) {
    console.log('register...');
    
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/account', true);
    xhr.onreadystatechange = function() {
      console.log('READY STATE CHANGE!')
      console.log(this.readyState);
      console.log(this.status);
      
      
      if (this.readyState === XMLHttpRequest.DONE) {
        console.log('DONE!');
        console.log(this.responseText)
      }
    };
    
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
      foo: 'bar',
      username: document.getElementById('username').value,
      name: document.getElementById('name').value
    }))
    
    
    e.preventDefault();
  });
};
