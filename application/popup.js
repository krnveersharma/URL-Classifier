document.addEventListener('DOMContentLoaded', () => {
  // Get the URL of the current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0].url;
    console.log(url);

    // Make a POST request to Flask server
    fetch('http://127.0.0.1:5000/extract_features_and_predict', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url })
    })
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    })
    .then(data => {
      // Print the output to the console or do whatever you want with it
      console.log(data);
      if(data.predictions==1){
              document.getElementById('result').textContent = "Possibly Phished"; // assuming the response contains 'predictions' field

      }
      else{
              document.getElementById('result').textContent = "Legit"; // assuming the response contains 'predictions' field

      }
    })
    .catch(error => {
      console.error('There was a problem with the fetch operation:', error);
    });
  });
});
