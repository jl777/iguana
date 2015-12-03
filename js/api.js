var SPNAPI = (function(SPNAPI, $, undefined) {

    SPNAPI.methods = {};
    SPNAPI.pages = ["Settings","Jay", "Debug","Wallet", "Tradebots","PAX","MGW","Atomic", "Jumblr", "pangea", "InstantDEX"];
    SPNAPI.pageContent = {};
    SPNAPI.page = "welcome";


    $(document).ready(function() {

        //load Pages into the navbar
        $.each(SPNAPI.pages, function( index, value ) {
            $("#welcome").after('<li class="navigation" data-page="'+value+'"><a href="#">'+value+'</a></li>');
        });


        $(".navigation").on("click", function () {

            var page = $(this).data("page");
            $(".navigation").removeClass("active");
            $(".hljs").html("JSON response");
            SPNAPI.loadSite(page);

        });

        $(".page").hide();
        $("#welcome_page").show();
    $(".submit_api_request").on("click", function () {

    if ( SPNAPI.page == "Jay" ) SPNAPI.handleJay();
    else SPNAPI.submitRequest();
    });

        $(".submit_api_request").on("click", function () {

            SPNAPI.submitRequest();

        });

        $(".clear-response").on("click", function () {

            $(".hljs").html("JSON response");

        });

    });

    SPNAPI.submitRequest = function(e) {

        var request = $(".json_submit_url").html();

        postCall('SuperNET', request, function(jsonstr)
        {
            $(".debuglogdebuglog").append(jsonstr);
            common.logMessage(jsonstr + '\n');

            $(".hljs").html(jsonstr);

        });
    };

              
              SPNAPI.handleJay = function(e)
              {
              var request = JSON.parse($(".json_submit_url").html());
              console.log(request);
              if(request.method == "NxtAPI")
              {
              console.log(request.requestType);
              Jay.request(request.requestType, JSON.parse(request.params), function(ans) {
                          $(".hljs").html(ans);
                          })
              }
              else if(request.method == "status")
              {
              $(".hljs").html("{'status':'doing alright'}");
              }
              else if(request.method == "signBytes")
              {
              var out = converters.byteArrayToHexString(signBytes(converters.hexStringToByteArray(request.bytes), request.secretPhrase));
              var ret = {};
              ret.signature = out;
              $(".hljs").html(JSON.stringify(ret));
              }
              else if(request.method == "createToken")
              {
              var out = createToken(request.data, request.secretPhrase);
              var ret = {};
              ret.token = out;
              $(".hljs").html(JSON.stringify(ret));
              }
              else if(request.method == "parseToken")
              {
              var out = parseToken(request.token, request.data);
              $(".hljs").html(JSON.stringify(out));
              }
              console.log(request);
              }

    return SPNAPI;
}(SPNAPI || {}, jQuery));
