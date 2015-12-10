/// <reference path="..\jquery-2.1.4.min.js" />

var coinManagement = {};

// Classes
coinManagement.Coin = function(_id, _symbol, _description, _statusId) {
	this.Id = _id;
	this.Symbol = _symbol;
	this.Description = _description;
	this.StatusId = _statusId;

	//coinManagement.log('Coin Mgmt : Coin constructed');
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

	// KCL : Keep Code Left pattern

	// Check if JSON is valid
	if (coin === null || coin === undefined || coin.length > 0) {
		console.log('Coin Mgmt : Can not add coin, invalid record');
		return false;
	}

	// Check if the JSON could be casted onto coin object
	if (false) {
		Console.log('Coin Mgmt : Invalid JSON');
		console.log(coin);
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
		var items = JSON.parse(localStorage.getItem('coinMgmt_savedCoins'));
		items.forEach(function(element) {
			// TODO : Insert Coin
			console.log('Coin Mgmt : Coin saved to localstorage', element);
		}, this);

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

	coinManagement.log(temp);
	localStorage.removeItem('coinMgmt_savedCoins');
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
	return '<tr><td>' + objCoin.Symbol + '</td><td>' + objCoin.Description + '</td><td>' + coinManagement.GetStatusNameHtml(objCoin.StatusId) + '</td></tr>';
};


coinManagement.log = function(message) {
	if (coinManagement.loggingEnabled == false) {
		return;
	}
	console.log(message);
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
			coinManagement.log('Coin Mgmt : Invalid Status ID : ' + id);
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


/// --------------
/// Event Handlers
/// --------------
$('#Coins_refresh').click(function() {
	coinManagement.Get();
	coinManagement.RenderGrid();
});