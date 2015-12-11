/// <reference path="..\jquery-2.1.4.min.js" />

var coinManagement = {};

// Classes
coinManagement.Coin = function(_id, _symbol, _description, _statusId) {
	this.Id = _id;
	this.Symbol = _symbol;
	this.Description = _description;
	this.StatusId = _statusId;

	//coinManagement.log(Coin constructed');
};

coinManagement.CoinStatus = function(_id, _name) {
	this.Id = _id;
	this.Name = _name;
};


// Initialization

coinManagement.loggingEnabled = true;
coinManagement.coins = [];

coinManagement.CoinStatuses = [
	new coinManagement.CoinStatus(1, 'Dormant'),
	new coinManagement.CoinStatus(2, 'Launched'),
	new coinManagement.CoinStatus(3, 'Started'),
	new coinManagement.CoinStatus(4, 'Paused')
];

/// ------------------------------
/// Coin Management JS API Methods
/// ------------------------------

// Inserts a new coin
coinManagement.Post = function(coin) {

	var objCoin = {};

	// Check if JSON is valid
	if (coin === null || coin === undefined || coin.length > 0) {
		coinManagement.log('Can not add coin, invalid record');
		return false;
	}

	// Check if the JSON could be casted onto coin object
	if (false) {
		Console.log('Invalid JSON');
		coinManagement.log(coin);
		return false;
	}

	// Object oriented javascript : create a new instance of class 'Coin'
	objCoin = {};

	coinManagement.coins.push(objCoin);

	// poor man's templating
	var htmlCoin = coinManagement.objToHtml(objCoin);
	$('#Coins_table tbody').append(htmlCoin);

	return true;
};

coinManagement.Get = function() {

	if (localStorage.getItem('coinMgmt_savedCoins') != null && localStorage.getItem('coinMgmt_savedCoins') != undefined) {
		coinManagement.coins = JSON.parse(localStorage.getItem('coinMgmt_savedCoins'));
		coinManagement.log(coinManagement.coins.length + ' records found in localStorage');
		coinManagement.RenderGrid();
		return;
	}

	// Test Data
	coinManagement.coins = [];
	coinManagement.coins = [
		new coinManagement.Coin(1, 'Sym1', 'Desc1', 1),
		new coinManagement.Coin(2, 'Sym2', 'Desc2', 2),
		new coinManagement.Coin(3, 'Sym3', 'Desc3', 3),
		new coinManagement.Coin(4, 'Sym4', 'Desc4', 4)
	];

	var temp = JSON.stringify(coinManagement.coins);
	localStorage.setItem('coinMgmt_savedCoins', temp);

	//coinManagement.log(temp);
	//localStorage.removeItem('coinMgmt_savedCoins');
};

coinManagement.GetById = function(id) {
	for (var index = 0; index < coinManagement.coins.length; index++) {
		if (coinManagement.coins[index].Id == id) {
			return coinManagement.coins[index];
		}
	}
};

coinManagement.RenderGrid = function() {
	var coinsTableBody = document.getElementById('Coins_table').getElementsByTagName('tbody')[0];
	coinsTableBody.innerHTML = '';
	coinManagement.coins.forEach(function(element) {
		var htmlCoin = coinManagement.objToHtml(element);
		coinsTableBody.innerHTML += htmlCoin;
	});
}

/// ----------------------------------
/// Helper methods for Coin Management
/// ----------------------------------

coinManagement.jsonToObj = function(jsonString) {
	return {};
};

coinManagement.objToJson = function(objCoin) {
	return '';
};

coinManagement.objToHtml = function(objCoin) {
	if (objCoin == null || objCoin == undefined) {
		return '';
	}
	return '<tr><td>' + objCoin.Symbol + '</td><td>' + objCoin.Description + '</td><td>' + coinManagement.GetStatusNameHtml(objCoin.StatusId) + '</td><td>' + coinManagement.getActionButton(objCoin.Id) + '</td></tr>';
};


coinManagement.log = function(message) {
	if (coinManagement.loggingEnabled == false) {
		return;
	}
	console.log('Coin Mgmt:', message);
};

coinManagement.GetStatusNameHtml = function(id) {
	var result = coinManagement.GetStatusName(id);

	switch (id) {
		case 1:
			return '<span class="label label-info">' + result + '</span>';
			break;

		case 2:
			return '<span class="label label-primary">' + result + '</span>';
			break;

		case 3:
			return '<span class="label label-success">' + result + '</span>';
			break;

		case 4:
			return '<span class="label label-danger">' + result + '</span>';
			break;

		default:
			coinManagement.log('Invalid Status ID : ' + id);
			return '<span class="label label-default">#Invalid</span>';
			break;
	}

};

coinManagement.GetStatusName = function(id) {
	for (var index = 0; index < coinManagement.CoinStatuses.length; index++) {
		if (coinManagement.CoinStatuses[index].Id == id) {
			return coinManagement.CoinStatuses[index].Name;
		}
	}
};


coinManagement.getActionButton = function(id) {
	// return '<button class="btn btn-default coinMgmtActionButton" data-id=' + id + ' onclick=\'alert(\"test\");\'>Button</button>';
	return '<button class="btn btn-default coinMgmtActionButton" data-id=' + id + '>Button</button>';
};


/// --------------
/// Event Handlers
/// --------------
$('#Coins_refresh').click(function() {
	coinManagement.Get();
	coinManagement.RenderGrid();

	var e = document.getElementsByClassName('coinMgmtActionButton');
	for (var index = 0; index < e.length; index++) {
		e[index].setAttribute('onclick', 'actionButtonClick(' + e[index].getAttribute('data-id') + ');');
	}

});

// $('#Coins_add').click(function() {

// });

var actionButtonClick = function(id) {
	coinManagement.log('Coin ID : ' + id);
	var temp = coinManagement.GetById(id);
	coinManagement.log(temp);
};

$(function(){
	var select = document.getElementById('ddStatus');
	for (var i = 0; i < coinManagement.CoinStatuses.length; i++) {
		var option = document.createElement('option');
		option.value = coinManagement.CoinStatuses[i].Id
		option.textContent = coinManagement.CoinStatuses[i].Name;
		select.appendChild(option);
	};
});