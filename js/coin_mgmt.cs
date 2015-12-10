var coinManagement = function(coinManagement, $, undefined) {


	coinManagement.coin = {};
	coinManagement.coin.Id;
	coinManagement.coin.Symbol;
	coinManagement.coin.Description;
	coinManagement.coin.StatusId;
	
	coinManagement.CoinStatus = {};
	coinManagement.CoinStatus.Id;
	coinManagement.CoinStatus.Name;
	
	coinManagement.CoinStatuses = [
		{ Id : 1, Name : 'Status1'},	
		{ Id : 2, Name : 'Status2'},	
		{ Id : 3, Name : 'Status3'},	
		{ Id : 4, Name : 'Status4'}	
	];
	
	coinManagement.coins = [];

	/// ------------------------------
	/// Coin Management JS API Methods
	/// ------------------------------

	// Inserts a new coin
	coinManagement.Post = function (coin) {
		
		var objCoin = {};
		
		// KCL : Keep Code Left pattern
		
		// Check if JSON is valid
		if(coin === null || coin === undefined || coin.length > 0){
			console.log('Coin Mgmt : Can not add coin, invalid record');
			return false;
		}
		
		// Check if the JSON could be casted onto coin object
		if(false) {
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
	
	coinManagement.Get = function () {
		
		coinManagement.coins = [];
		
		if(localStorage['coingMgmt_savedCoins']){
			var items = JSON.parse(localStorage['coingMgmt_savedCoins']);
			items.forEach(function(element) {
				// TODO : Insert Coin
				console.log('Coin Mgmt : Inserting coin', element);
		}, this);
	}
	};
	
	/// ----------------------------------
	/// Helper methods for Coin Management
	/// ----------------------------------
	
	coinManagement.jsonToObj = function (jsonString) {
		return {};
	};
	
	coinManagement.objToJson = function (objCoin) {
		return "";
	};

	coinManagement.objToHtml = function (objCoin) {
		return "";
	};
}