
var date = new Date();
day_no = date.getDay();
days = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
today = days[day_no];
heading = 'Today\'s Record ('+today+' '+date.getDate()+'/'+(date.getMonth()+1)+'/'+date.getFullYear()+')';
document.getElementById("dat").innerHTML = heading;
