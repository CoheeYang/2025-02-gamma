// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.0;
//@audit Q7: any compiler issue with ^0.8.0?

import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts/utils/math/SignedSafeMath.sol";

import "../../interfaces/gmx/IDataStore.sol";
import "../StructData.sol";

// @title MarketUtils
// @dev Library for market functions
library MarketUtils {
    //@audit Q8: any potential vulnerabilities of the safeCast&SignedSafeMath lib?
    using SignedSafeMath for int256;
    using SafeCast for int256;
    using SafeCast for uint256;
    //@audit Q：这个lib规定精度是10^30
    uint256 public constant FLOAT_PRECISION = 10 ** 30;
    bytes32 public constant OPEN_INTEREST = keccak256(abi.encode("OPEN_INTEREST"));
    bytes32 public constant MIN_COLLATERAL_FACTOR_FOR_OPEN_INTEREST_MULTIPLIER = keccak256(abi.encode("MIN_COLLATERAL_FACTOR_FOR_OPEN_INTEREST_MULTIPLIER"));
    bytes32 public constant MIN_COLLATERAL_FACTOR = keccak256(abi.encode("MIN_COLLATERAL_FACTOR"));

    struct WillPositionCollateralBeSufficientValues {
        uint256 positionSizeInUsd;
        uint256 positionCollateralAmount;
        int256 realizedPnlUsd;
        int256 openInterestDelta;
    }
//✅没看出啥问题
    function willPositionCollateralBeSufficient(
        IDataStore dataStore,
        MarketProps memory market,
        MarketPrices memory prices,
        bool isLong,
        WillPositionCollateralBeSufficientValues memory values
    ) external view returns (bool, int256) {
        //拿卖方的市场价格作为抵押物价格✅
        PriceProps memory collateralTokenPrice = prices.shortTokenPrice;

        //抵押物价值=抵押物数量*抵押物市价的最低价格min✅
        int256 remainingCollateralUsd = values.positionCollateralAmount.toInt256() * collateralTokenPrice.min.toInt256();

        // deduct realized pnl if it is negative since this would be paid from✅
        // the position's collateral
        //浮亏加抵押物剩余价值，如果最终剩余价值为负数，返回false和亏钱数
        if (values.realizedPnlUsd < 0) {
            remainingCollateralUsd = remainingCollateralUsd + values.realizedPnlUsd;
        }

        if (remainingCollateralUsd < 0) {
            return (false, remainingCollateralUsd);
        }


//////如果不亏钱，判断是否有足够的抵押物
        //✅得到最小抵押率
        // the min collateral factor will increase as the open interest for a market increases
        // this may lead to previously created limit increase orders not being executable
        //
        // the position's pnl is not factored into the remainingCollateralUsd value, since
        // factoring in a positive pnl may allow the user to manipulate price and bypass this check
        // it may be useful to factor in a negative pnl for this check, this can be added if required
        uint256 minCollateralFactor = MarketUtils.getMinCollateralFactorForOpenInterest(
            dataStore,
            market,
            values.openInterestDelta,
            isLong
        );
        //✅取数，得到市场的最小抵押率
        uint256 minCollateralFactorForMarket = MarketUtils.getMinCollateralFactor(dataStore, market.marketToken);
        // use the minCollateralFactor for the market if it is larger
        if (minCollateralFactorForMarket > minCollateralFactor) {
            minCollateralFactor = minCollateralFactorForMarket;
        }

        int256 minCollateralUsdForLeverage = applyFactor(values.positionSizeInUsd, minCollateralFactor).toInt256();
        bool willBeSufficient = remainingCollateralUsd >= minCollateralUsdForLeverage;

        return (willBeSufficient, remainingCollateralUsd);
    }

    //✅审不到
    // @dev get the min collateral factor for open interest multiplier
    // @param dataStore DataStore
    // @param market the market to check
    // @param isLong whether it is for the long or short side 
    function getMinCollateralFactorForOpenInterestMultiplier(IDataStore dataStore, address market, bool isLong) internal view returns (uint256) {
        return dataStore.getUint(minCollateralFactorForOpenInterestMultiplierKey(market, isLong));
    }
    //✅
    // @dev get the min collateral factor for open interest ！通过未平仓量得到最小抵押率
    // @param dataStore DataStore
    // @param market the market to check
    // @param longToken the long token of the market
    // @param shortToken the short token of the market
    // @param openInterestDelta the change in open interest
    // @param isLong whether it is for the long or short side
    function getMinCollateralFactorForOpenInterest(
        IDataStore dataStore,
        MarketProps memory market,
        int256 openInterestDelta,
        bool isLong
    ) internal view returns (uint256) {
        uint256 openInterest = getOpenInterest(dataStore, market, isLong);//✅得到单方的未平仓量
        openInterest = sumReturnUint256(openInterest, openInterestDelta);//✅更新数据？上面的单方未平仓量+未平仓量的变化值
        uint256 multiplierFactor = getMinCollateralFactorForOpenInterestMultiplier(dataStore, market.marketToken, isLong);//✅从另外合约取数规定的multiplierFactor
        return applyFactor(openInterest, multiplierFactor);//✅前两个参数v和f的精度对其10^30则没问题，得到最小抵押率，这个抵押率是随未平仓量增加而线性增加
    }


    // ✅得到多空两方的未平仓量之和
    // @dev get the open interest of a market
    // @param dataStore DataStore
    // @param market the market to check
    // @param longToken the long token of the market
    // @param shortToken the short token of the market
    function getOpenInterest(
        IDataStore dataStore,
        MarketProps memory market
    ) internal view returns (uint256) {
        uint256 longOpenInterest = getOpenInterest(dataStore, market, true);
        uint256 shortOpenInterest = getOpenInterest(dataStore, market, false);

        return longOpenInterest + shortOpenInterest;
    }

    //✅得到单方的未平仓量
    // @dev get either the long or short open interest for a market
    // @param dataStore DataStore
    // @param market the market to check
    // @param longToken the long token of the market
    // @param shortToken the short token of the market
    // @param isLong whether to get the long or short open interest
    // @return the long or short open interest for a market
    function getOpenInterest(
        IDataStore dataStore,
        MarketProps memory market,
        bool isLong
    ) internal view returns (uint256) {
        //如果市场longToken和shortToken相同，则divisor为2，反之为1  为2是因为最后算的两个数一样，会重复计算
        uint256 divisor = getPoolDivisor(market.longToken, market.shortToken);
        uint256 openInterestUsingLongTokenAsCollateral = getOpenInterest(dataStore, market.marketToken, market.longToken, isLong, divisor);
        uint256 openInterestUsingShortTokenAsCollateral = getOpenInterest(dataStore, market.marketToken, market.shortToken, isLong, divisor);

        return openInterestUsingLongTokenAsCollateral + openInterestUsingShortTokenAsCollateral;
    }


    //✅他这个拿的是DataStore的数据,通过openInterestKey得到openInterest的值
    // @dev the long and short open interest for a market based on the collateral token used
    // @param dataStore DataStore
    // @param market the market to check
    // @param collateralToken the collateral token to check
    // @param isLong whether to check the long or short side
    function getOpenInterest(
        IDataStore dataStore,
        address market,
        address collateralToken,
        bool isLong,
        uint256 divisor
    ) internal view returns (uint256) {
        return dataStore.getUint(openInterestKey(market, collateralToken, isLong)) / divisor;
    }


    //✅
    // this is used to divide the values of getPoolAmount and getOpenInterest
    // if the longToken and shortToken are the same, then these values have to be divided by two
    // to avoid double counting
    function getPoolDivisor(address longToken, address shortToken) internal pure returns (uint256) {
        return longToken == shortToken ? 2 : 1;
    }

    //✅
    function sumReturnUint256(uint256 a, int256 b) internal pure returns (uint256) {
        if (b > 0) {
            return a + uint256(b);
        }

        return a - uint256(-b);
    }

    /** 
     * ✅v*f/10^30，资产价值*抵押倍率得到最小抵押物价值
     * Applies the given factor to the given value and returns the result.
     *
     * @param value The value to apply the factor to.
     * @param factor The factor to apply.
     * @return The result of applying the factor to the value.
     */
    function applyFactor(uint256 value, uint256 factor) internal pure returns (uint256) {
        return Math.mulDiv(value, factor, FLOAT_PRECISION);
    }

    //✅
    // @dev get the min collateral factor
    // @param dataStore DataStore
    // @param market the market to check
    function getMinCollateralFactor(IDataStore dataStore, address market) internal view returns (uint256) {
        return dataStore.getUint(minCollateralFactorKey(market));
    }
    //✅
    // @dev key for open interest
    // @param market the market to check
    // @param collateralToken the collateralToken to check
    // @param isLong whether to check the long or short open interest
    // @return key for open interest
    function openInterestKey(address market, address collateralToken, bool isLong) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            OPEN_INTEREST,
            market,
            collateralToken,
            isLong
        ));
    }
    //✅
    // @dev the min collateral factor for open interest multiplier key
    // @param the market for the factor
   function minCollateralFactorForOpenInterestMultiplierKey(address market, bool isLong) internal pure returns (bytes32) {
       return keccak256(abi.encode(
           MIN_COLLATERAL_FACTOR_FOR_OPEN_INTEREST_MULTIPLIER,
           market,
           isLong
       ));
    }
    //✅
    // @dev the min collateral factor key
   // @param the market for the min collateral factor
   function minCollateralFactorKey(address market) internal pure returns (bytes32) {
       return keccak256(abi.encode(
           MIN_COLLATERAL_FACTOR,
           market
       ));
    }
}
