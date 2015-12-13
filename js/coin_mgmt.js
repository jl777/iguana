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

coinManagement.log = function(message) {
	if (coinManagement.loggingEnabled == false) {
		return;
	}
	console.log('Coin Mgmt:', message);
};

// Inserts a new coin
coinManagement.Post = function(objCoin) {

	// Check if JSON is valid
	if (objCoin === null || objCoin === undefined) {
		coinManagement.log('Can not add coin, invalid record');
		return false;
	}

	coinManagement.coins.push(objCoin);

	// Update Local Storage
	updateLocalStorage();

	return true;
};

coinManagement.Get = function() {

	// Clear Local Storage
	//localStorage.removeItem('coinMgmt_savedCoins');

	getCoinsFromLocalStorage();

	// Test Data - call API here
	coinManagement.coins = [];
	coinManagement.coins = [
		new coinManagement.Coin(1, 'Sym1', 'Desc1', 1),
		new coinManagement.Coin(2, 'Sym2', 'Desc2', 2),
		new coinManagement.Coin(3, 'Sym3', 'Desc3', 3),
		new coinManagement.Coin(4, 'Sym4', 'Desc4', 4)
	];

	updateLocalStorage();

};

coinManagement.GetById = function(id) {
	for (var index = 0; index < coinManagement.coins.length; index++) {
		if (coinManagement.coins[index].Id == id) {
			return coinManagement.coins[index];
		}
	}
};

coinManagement.GetCoinIndex = function(id) {
	for (var index = 0; index < coinManagement.coins.length; index++) {
		if (coinManagement.coins[index].Id == id) {
			return index;
		}
	}
};

coinManagement.RenderGrid = function() {
	var coinsTableBody = document.getElementById('Coins_table').getElementsByTagName('tbody')[0];
	coinsTableBody.innerHTML = '';
	coinManagement.coins.forEach(function(element) {
		var htmlCoin = objToHtml(element);
		coinsTableBody.innerHTML += htmlCoin;
	});
}

coinManagement.Delete = function(id) {

	coinManagement.log('Deleting Coin ID : ' + id);
	var index = coinManagement.GetCoinIndex(id);
	coinManagement.coins.splice(index, 1);

	var temp = JSON.stringify(coinManagement.coins);
	localStorage.setItem('coinMgmt_savedCoins', temp);

	loadData();
}



/// --------------
/// Event Handlers
/// --------------
$('#Coins_refresh').click(function() {
	loadData();
});

// $('#Coins_add').click(function() {

// });


$('#btnSaveCoinForm').click(function(event) {

	var saveButton = document.getElementById('btnSaveCoinForm');
	saveButton.removeAttribute('data-dismiss');

	if (coinEditFormIsValid() == false) {
		return;
	}

	var txt_symbol = document.getElementById('txtSymbol').value;
	var txt_description = document.getElementById('txtDescription').value;
	var dd_Status = document.getElementById('ddStatus').value;

	// save data

	// KNOWN ISSUE : I AM AWARE THAT HARD CODING THE COIN ID TO 5 WOULD CAUSE PROBLEMS IN SOME SCENARIOS BUT THIS IS FOR TEMPORARY TESTING, THE API SHOULD RETURN THE ACTUAL COIN ID WHEN SAVED / OTHERWISE THE ID'S NEEDS TO BE TRACKED LOCALLY.

	var objNewCoin = new coinManagement.Coin(5, txt_symbol, txt_description, dd_Status);
	coinManagement.log('New Coin');
	coinManagement.log(objNewCoin);
	coinManagement.Post(objNewCoin);

	// reset form
	coinEditFormReset();
	saveButton.setAttribute('data-dismiss', 'modal');
	loadData();
});

$(function() {
	var select = document.getElementById('ddStatus');
	for (var i = 0; i < coinManagement.CoinStatuses.length; i++) {
		var option = document.createElement('option');
		option.value = coinManagement.CoinStatuses[i].Id
		option.textContent = coinManagement.CoinStatuses[i].Name;
		select.appendChild(option);
	};
	loadData();
});



/// ----------------------------------
/// Helper methods for Coin Management
/// ----------------------------------

var getCoinsFromLocalStorage = function() {
	if (chrome.storage != null && chrome.storage != undefined) {
		chrome.storage.sync.get('coinMgmt_savedCoins', function(localData) {
			if (!chrome.runtime.error) {
				coinManagement.log('getting data from chrome local storage');
				coinManagement.log(savedCoins);
				coinManagement.coins = localData.coinMgmt_savedCoins;
				coinManagement.RenderGrid();
				return true;
			}
		});
	} else {
		coinManagement.log('#Err : getting from chrome local storage');
		coinManagement.log('getting data from localStorage');
		if (localStorage.getItem('coinMgmt_savedCoins') != null && localStorage.getItem('coinMgmt_savedCoins') != undefined) {
			coinManagement.coins = JSON.parse(localStorage.getItem('coinMgmt_savedCoins'));
			coinManagement.log(coinManagement.coins.length + ' records found in localStorage');
			coinManagement.RenderGrid();
			return true;
		}
	}
}

var updateLocalStorage = function() {
	var temp = JSON.stringify(coinManagement.coins);
	if (chrome.storage != null && chrome.storage != undefined) {
		chrome.storage.sync.set({
			'coinMgmt_savedCoins': temp
		}, function() {
			if (!chrome.runtime.error) {
				alert('chrome local storage udated');
				coinManagement.log('chrome local storage udated');
				message('Local storage udate+d');
			}
		});
	} else {
		coinManagement.log('#Err : updating chrome local storage');
		coinManagement.log('saving data in localStorage');
		localStorage.setItem('coinMgmt_savedCoins', temp);
	}
	return true;
};

var jsonToObj = function(jsonString) {
	return {};
};

var objToJson = function(objCoin) {
	return '';
};

var objToHtml = function(objCoin) {
	if (objCoin == null || objCoin == undefined) {
		return '';
	}
	return '<tr><td>' + objCoin.Symbol + '</td><td>' + objCoin.Description + '</td><td>' + GetStatusNameHtml(objCoin.StatusId) + '</td><td>' + getActionButton(objCoin.Id) + '</td></tr>';
};

var GetStatusNameHtml = function(id) {
	var result = GetStatusName(id);

	switch (id) {
		case 1:
		case '1':
			return '<span class="label label-info">' + result + '</span>';
			break;

		case 2:
		case '2':
			return '<span class="label label-primary">' + result + '</span>';
			break;

		case 3:
		case '3':
			return '<span class="label label-success">' + result + '</span>';
			break;

		case 4:
		case '4':
			return '<span class="label label-danger">' + result + '</span>';
			break;

		default:
			coinManagement.log('Invalid Status ID : ' + id);
			return '<span class="label label-default">#Invalid</span>';
			break;
	}

};

var GetStatusName = function(id) {
	for (var index = 0; index < coinManagement.CoinStatuses.length; index++) {
		if (coinManagement.CoinStatuses[index].Id == id) {
			return coinManagement.CoinStatuses[index].Name;
		}
	}
};

var getActionButton = function(id) {
	// return '<button class="btn btn-default coinMgmtActionButton" data-id=' + id + ' onclick=\'alert(\"test\");\'>Button</button>';
	return '<button class="btn btn-default coinMgmtActionButton" data-id=' + id + '>Delete</button>';
};


var loadData = function() {
	coinManagement.Get();
	coinManagement.RenderGrid();

	var e = document.getElementsByClassName('coinMgmtActionButton');
	for (var index = 0; index < e.length; index++) {
		e[index].setAttribute('onclick', 'actionButtonClick(' + e[index].getAttribute('data-id') + ');');
	}
};

var actionButtonClick = function(id) {
	coinManagement.Delete(id);
};

var coinEditFormReset = function() {
	document.getElementById('txtSymbol').value = '';
	document.getElementById('txtDescription').value = '';
	document.getElementById('ddStatus').value = 1;
}

var coinEditFormIsValid = function() {

	var txt_symbol = document.getElementById('txtSymbol').value;
	var txt_description = document.getElementById('txtDescription').value;
	var dd_Status = document.getElementById('ddStatus').value;

	var symbol_group = document.getElementById('txtSymbolGroup');
	var description_group = document.getElementById('txtDescriptionGroup');
	var status_group = document.getElementById('ddStatusGroup');

	symbol_group.removeAttribute('class');
	symbol_group.setAttribute('class', 'form-group');

	description_group.removeAttribute('class');
	description_group.setAttribute('class', 'form-group');

	status_group.removeAttribute('class');
	status_group.setAttribute('class', 'form-group');

	if (txt_symbol == null || txt_symbol == undefined || txt_symbol.length == 0) {
		symbol_group.removeAttribute('class');
		symbol_group.setAttribute('class', 'has-error form-group');
		return false;
	} else if (txt_description == null || txt_description == undefined || txt_description.length == 0) {
		description_group.removeAttribute('class');
		description_group.setAttribute('class', 'has-error form-group');
		return false;
	} else if (dd_Status == null || dd_Status == undefined || dd_Status.length == 0) {
		status_group.removeAttribute('class');
		status_group.setAttribute('class', 'has-error form-group');
		return false;
	}
}