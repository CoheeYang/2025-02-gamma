// // File: openzeppelin-solidity/contracts/utils/EnumerableSet.sol



// pragma solidity >=0.6.0 <0.8.0;

// /**
//  * @dev Library for managing
//  * https://en.wikipedia.org/wiki/Set_(abstract_data_type)[sets] of primitive
//  * types.
//  *
//  * Sets have the following properties:
//  *
//  * - Elements are added, removed, and checked for existence in constant time
//  * (O(1)).
//  * - Elements are enumerated in O(n). No guarantees are made on the ordering.
//  *
//  * ```
//  * contract Example {
//  *     // Add the library methods
//  *     using EnumerableSet for EnumerableSet.AddressSet;
//  *
//  *     // Declare a set state variable
//  *     EnumerableSet.AddressSet private mySet;
//  * }
//  * ```
//  *
//  * As of v3.3.0, sets of type `bytes32` (`Bytes32Set`), `address` (`AddressSet`)
//  * and `uint256` (`UintSet`) are supported.
//  */
// library EnumerableSet {
//     // To implement this library for multiple types with as little code
//     // repetition as possible, we write it in terms of a generic Set type with
//     // bytes32 values.
//     // The Set implementation uses private functions, and user-facing
//     // implementations (such as AddressSet) are just wrappers around the
//     // underlying Set.
//     // This means that we can only create new EnumerableSets for types that fit
//     // in bytes32.

//     struct Set {
//         // Storage of set values
//         bytes32[] _values;

//         // Position of the value in the `values` array, plus 1 because index 0
//         // means a value is not in the set.
//         mapping (bytes32 => uint256) _indexes;
//     }

//     /**
//      * @dev Add a value to a set. O(1).
//      *
//      * Returns true if the value was added to the set, that is if it was not
//      * already present.
//      */
//     function _add(Set storage set, bytes32 value) private returns (bool) {
//         if (!_contains(set, value)) {
//             set._values.push(value);
//             // The value is stored at length-1, but we add 1 to all indexes
//             // and use 0 as a sentinel value
//             set._indexes[value] = set._values.length;
//             return true;
//         } else {
//             return false;
//         }
//     }

//     /**
//      * @dev Removes a value from a set. O(1).
//      *
//      * Returns true if the value was removed from the set, that is if it was
//      * present.
//      */
//     function _remove(Set storage set, bytes32 value) private returns (bool) {
//         // We read and store the value's index to prevent multiple reads from the same storage slot
//         uint256 valueIndex = set._indexes[value];

//         if (valueIndex != 0) { // Equivalent to contains(set, value)
//             // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
//             // the array, and then remove the last element (sometimes called as 'swap and pop').
//             // This modifies the order of the array, as noted in {at}.

//             uint256 toDeleteIndex = valueIndex - 1;
//             uint256 lastIndex = set._values.length - 1;

//             // When the value to delete is the last one, the swap operation is unnecessary. However, since this occurs
//             // so rarely, we still do the swap anyway to avoid the gas cost of adding an 'if' statement.

//             bytes32 lastvalue = set._values[lastIndex];

//             // Move the last value to the index where the value to delete is
//             set._values[toDeleteIndex] = lastvalue;
//             // Update the index for the moved value
//             set._indexes[lastvalue] = toDeleteIndex + 1; // All indexes are 1-based

//             // Delete the slot where the moved value was stored
//             set._values.pop();

//             // Delete the index for the deleted slot
//             delete set._indexes[value];

//             return true;
//         } else {
//             return false;
//         }
//     }

//     /**
//      * @dev Returns true if the value is in the set. O(1).
//      */
//     function _contains(Set storage set, bytes32 value) private view returns (bool) {
//         return set._indexes[value] != 0;
//     }

//     /**
//      * @dev Returns the number of values on the set. O(1).
//      */
//     function _length(Set storage set) private view returns (uint256) {
//         return set._values.length;
//     }

//    /**
//     * @dev Returns the value stored at position `index` in the set. O(1).
//     *
//     * Note that there are no guarantees on the ordering of values inside the
//     * array, and it may change when more values are added or removed.
//     *
//     * Requirements:
//     *
//     * - `index` must be strictly less than {length}.
//     */
//     function _at(Set storage set, uint256 index) private view returns (bytes32) {
//         require(set._values.length > index, "EnumerableSet: index out of bounds");
//         return set._values[index];
//     }

//     // Bytes32Set

//     struct Bytes32Set {
//         Set _inner;
//     }

//     /**
//      * @dev Add a value to a set. O(1).
//      *
//      * Returns true if the value was added to the set, that is if it was not
//      * already present.
//      */
//     function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {
//         return _add(set._inner, value);
//     }

//     /**
//      * @dev Removes a value from a set. O(1).
//      *
//      * Returns true if the value was removed from the set, that is if it was
//      * present.
//      */
//     function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {
//         return _remove(set._inner, value);
//     }

//     /**
//      * @dev Returns true if the value is in the set. O(1).
//      */
//     function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {
//         return _contains(set._inner, value);
//     }

//     /**
//      * @dev Returns the number of values in the set. O(1).
//      */
//     function length(Bytes32Set storage set) internal view returns (uint256) {
//         return _length(set._inner);
//     }

//    /**
//     * @dev Returns the value stored at position `index` in the set. O(1).
//     *
//     * Note that there are no guarantees on the ordering of values inside the
//     * array, and it may change when more values are added or removed.
//     *
//     * Requirements:
//     *
//     * - `index` must be strictly less than {length}.
//     */
//     function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {
//         return _at(set._inner, index);
//     }

//     // AddressSet

//     struct AddressSet {
//         Set _inner;
//     }

//     /**
//      * @dev Add a value to a set. O(1).
//      *
//      * Returns true if the value was added to the set, that is if it was not
//      * already present.
//      */
//     function add(AddressSet storage set, address value) internal returns (bool) {
//         return _add(set._inner, bytes32(uint256(value)));
//     }

//     /**
//      * @dev Removes a value from a set. O(1).
//      *
//      * Returns true if the value was removed from the set, that is if it was
//      * present.
//      */
//     function remove(AddressSet storage set, address value) internal returns (bool) {
//         return _remove(set._inner, bytes32(uint256(value)));
//     }

//     /**
//      * @dev Returns true if the value is in the set. O(1).
//      */
//     function contains(AddressSet storage set, address value) internal view returns (bool) {
//         return _contains(set._inner, bytes32(uint256(value)));
//     }

//     /**
//      * @dev Returns the number of values in the set. O(1).
//      */
//     function length(AddressSet storage set) internal view returns (uint256) {
//         return _length(set._inner);
//     }

//    /**
//     * @dev Returns the value stored at position `index` in the set. O(1).
//     *
//     * Note that there are no guarantees on the ordering of values inside the
//     * array, and it may change when more values are added or removed.
//     *
//     * Requirements:
//     *
//     * - `index` must be strictly less than {length}.
//     */
//     function at(AddressSet storage set, uint256 index) internal view returns (address) {
//         return address(uint256(_at(set._inner, index)));
//     }


//     // UintSet

//     struct UintSet {
//         Set _inner;
//     }

//     /**
//      * @dev Add a value to a set. O(1).
//      *
//      * Returns true if the value was added to the set, that is if it was not
//      * already present.
//      */
//     function add(UintSet storage set, uint256 value) internal returns (bool) {
//         return _add(set._inner, bytes32(value));
//     }

//     /**
//      * @dev Removes a value from a set. O(1).
//      *
//      * Returns true if the value was removed from the set, that is if it was
//      * present.
//      */
//     function remove(UintSet storage set, uint256 value) internal returns (bool) {
//         return _remove(set._inner, bytes32(value));
//     }

//     /**
//      * @dev Returns true if the value is in the set. O(1).
//      */
//     function contains(UintSet storage set, uint256 value) internal view returns (bool) {
//         return _contains(set._inner, bytes32(value));
//     }

//     /**
//      * @dev Returns the number of values on the set. O(1).
//      */
//     function length(UintSet storage set) internal view returns (uint256) {
//         return _length(set._inner);
//     }

//    /**
//     * @dev Returns the value stored at position `index` in the set. O(1).
//     *
//     * Note that there are no guarantees on the ordering of values inside the
//     * array, and it may change when more values are added or removed.
//     *
//     * Requirements:
//     *
//     * - `index` must be strictly less than {length}.
//     */
//     function at(UintSet storage set, uint256 index) internal view returns (uint256) {
//         return uint256(_at(set._inner, index));
//     }
// }

// // File: openzeppelin-solidity/contracts/utils/Address.sol



// pragma solidity >=0.6.2 <0.8.0;

// /**
//  * @dev Collection of functions related to the address type
//  */
// library Address {
//     /**
//      * @dev Returns true if `account` is a contract.
//      *
//      * [IMPORTANT]
//      * ====
//      * It is unsafe to assume that an address for which this function returns
//      * false is an externally-owned account (EOA) and not a contract.
//      *
//      * Among others, `isContract` will return false for the following
//      * types of addresses:
//      *
//      *  - an externally-owned account
//      *  - a contract in construction
//      *  - an address where a contract will be created
//      *  - an address where a contract lived, but was destroyed
//      * ====
//      */
//     function isContract(address account) internal view returns (bool) {
//         // This method relies on extcodesize, which returns 0 for contracts in
//         // construction, since the code is only stored at the end of the
//         // constructor execution.

//         uint256 size;
//         // solhint-disable-next-line no-inline-assembly
//         assembly { size := extcodesize(account) }
//         return size > 0;
//     }

//     /**
//      * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
//      * `recipient`, forwarding all available gas and reverting on errors.
//      *
//      * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
//      * of certain opcodes, possibly making contracts go over the 2300 gas limit
//      * imposed by `transfer`, making them unable to receive funds via
//      * `transfer`. {sendValue} removes this limitation.
//      *
//      * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
//      *
//      * IMPORTANT: because control is transferred to `recipient`, care must be
//      * taken to not create reentrancy vulnerabilities. Consider using
//      * {ReentrancyGuard} or the
//      * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
//      */
//     function sendValue(address payable recipient, uint256 amount) internal {
//         require(address(this).balance >= amount, "Address: insufficient balance");

//         // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
//         (bool success, ) = recipient.call{ value: amount }("");
//         require(success, "Address: unable to send value, recipient may have reverted");
//     }

//     /**
//      * @dev Performs a Solidity function call using a low level `call`. A
//      * plain`call` is an unsafe replacement for a function call: use this
//      * function instead.
//      *
//      * If `target` reverts with a revert reason, it is bubbled up by this
//      * function (like regular Solidity function calls).
//      *
//      * Returns the raw returned data. To convert to the expected return value,
//      * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
//      *
//      * Requirements:
//      *
//      * - `target` must be a contract.
//      * - calling `target` with `data` must not revert.
//      *
//      * _Available since v3.1._
//      */
//     function functionCall(address target, bytes memory data) internal returns (bytes memory) {
//       return functionCall(target, data, "Address: low-level call failed");
//     }

//     /**
//      * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
//      * `errorMessage` as a fallback revert reason when `target` reverts.
//      *
//      * _Available since v3.1._
//      */
//     function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
//         return functionCallWithValue(target, data, 0, errorMessage);
//     }

//     /**
//      * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
//      * but also transferring `value` wei to `target`.
//      *
//      * Requirements:
//      *
//      * - the calling contract must have an ETH balance of at least `value`.
//      * - the called Solidity function must be `payable`.
//      *
//      * _Available since v3.1._
//      */
//     function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
//         return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
//     }

//     /**
//      * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
//      * with `errorMessage` as a fallback revert reason when `target` reverts.
//      *
//      * _Available since v3.1._
//      */
//     function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {
//         require(address(this).balance >= value, "Address: insufficient balance for call");
//         require(isContract(target), "Address: call to non-contract");

//         // solhint-disable-next-line avoid-low-level-calls
//         (bool success, bytes memory returndata) = target.call{ value: value }(data);
//         return _verifyCallResult(success, returndata, errorMessage);
//     }

//     /**
//      * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
//      * but performing a static call.
//      *
//      * _Available since v3.3._
//      */
//     function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
//         return functionStaticCall(target, data, "Address: low-level static call failed");
//     }

//     /**
//      * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
//      * but performing a static call.
//      *
//      * _Available since v3.3._
//      */
//     function functionStaticCall(address target, bytes memory data, string memory errorMessage) internal view returns (bytes memory) {
//         require(isContract(target), "Address: static call to non-contract");

//         // solhint-disable-next-line avoid-low-level-calls
//         (bool success, bytes memory returndata) = target.staticcall(data);
//         return _verifyCallResult(success, returndata, errorMessage);
//     }

//     function _verifyCallResult(bool success, bytes memory returndata, string memory errorMessage) private pure returns(bytes memory) {
//         if (success) {
//             return returndata;
//         } else {
//             // Look for revert reason and bubble it up if present
//             if (returndata.length > 0) {
//                 // The easiest way to bubble the revert reason is using memory via assembly

//                 // solhint-disable-next-line no-inline-assembly
//                 assembly {
//                     let returndata_size := mload(returndata)
//                     revert(add(32, returndata), returndata_size)
//                 }
//             } else {
//                 revert(errorMessage);
//             }
//         }
//     }
// }

// // File: openzeppelin-solidity/contracts/GSN/Context.sol



// pragma solidity >=0.6.0 <0.8.0;

// /*
//  * @dev Provides information about the current execution context, including the
//  * sender of the transaction and its data. While these are generally available
//  * via msg.sender and msg.data, they should not be accessed in such a direct
//  * manner, since when dealing with GSN meta-transactions the account sending and
//  * paying for execution may not be the actual sender (as far as an application
//  * is concerned).
//  *
//  * This contract is only required for intermediate, library-like contracts.
//  */
// abstract contract Context {
//     function _msgSender() internal view virtual returns (address payable) {
//         return msg.sender;
//     }

//     function _msgData() internal view virtual returns (bytes memory) {
//         this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
//         return msg.data;
//     }
// }

// // File: openzeppelin-solidity/contracts/access/AccessControl.sol



// pragma solidity >=0.6.0 <0.8.0;




// /**
//  * @dev Contract module that allows children to implement role-based access
//  * control mechanisms.
//  *
//  * Roles are referred to by their `bytes32` identifier. These should be exposed
//  * in the external API and be unique. The best way to achieve this is by
//  * using `public constant` hash digests:
//  *
//  * ```
//  * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
//  * ```
//  *
//  * Roles can be used to represent a set of permissions. To restrict access to a
//  * function call, use {hasRole}:
//  *
//  * ```
//  * function foo() public {
//  *     require(hasRole(MY_ROLE, msg.sender));
//  *     ...
//  * }
//  * ```
//  *
//  * Roles can be granted and revoked dynamically via the {grantRole} and
//  * {revokeRole} functions. Each role has an associated admin role, and only
//  * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
//  *
//  * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
//  * that only accounts with this role will be able to grant or revoke other
//  * roles. More complex role relationships can be created by using
//  * {_setRoleAdmin}.
//  *
//  * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
//  * grant and revoke this role. Extra precautions should be taken to secure
//  * accounts that have been granted it.
//  */
// abstract contract AccessControl is Context {
//     using EnumerableSet for EnumerableSet.AddressSet;
//     using Address for address;

//     struct RoleData {
//         EnumerableSet.AddressSet members;
//         bytes32 adminRole;
//     }

//     mapping (bytes32 => RoleData) private _roles;

//     bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

//     /**
//      * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
//      *
//      * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
//      * {RoleAdminChanged} not being emitted signaling this.
//      *
//      * _Available since v3.1._
//      */
//     event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

//     /**
//      * @dev Emitted when `account` is granted `role`.
//      *
//      * `sender` is the account that originated the contract call, an admin role
//      * bearer except when using {_setupRole}.
//      */
//     event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

//     /**
//      * @dev Emitted when `account` is revoked `role`.
//      *
//      * `sender` is the account that originated the contract call:
//      *   - if using `revokeRole`, it is the admin role bearer
//      *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
//      */
//     event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

//     /**
//      * @dev Returns `true` if `account` has been granted `role`.
//      */
//     function hasRole(bytes32 role, address account) public view returns (bool) {
//         return _roles[role].members.contains(account);
//     }

//     /**
//      * @dev Returns the number of accounts that have `role`. Can be used
//      * together with {getRoleMember} to enumerate all bearers of a role.
//      */
//     function getRoleMemberCount(bytes32 role) public view returns (uint256) {
//         return _roles[role].members.length();
//     }

//     /**
//      * @dev Returns one of the accounts that have `role`. `index` must be a
//      * value between 0 and {getRoleMemberCount}, non-inclusive.
//      *
//      * Role bearers are not sorted in any particular way, and their ordering may
//      * change at any point.
//      *
//      * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure
//      * you perform all queries on the same block. See the following
//      * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]
//      * for more information.
//      */
//     function getRoleMember(bytes32 role, uint256 index) public view returns (address) {
//         return _roles[role].members.at(index);
//     }

//     /**
//      * @dev Returns the admin role that controls `role`. See {grantRole} and
//      * {revokeRole}.
//      *
//      * To change a role's admin, use {_setRoleAdmin}.
//      */
//     function getRoleAdmin(bytes32 role) public view returns (bytes32) {
//         return _roles[role].adminRole;
//     }

//     /**
//      * @dev Grants `role` to `account`.
//      *
//      * If `account` had not been already granted `role`, emits a {RoleGranted}
//      * event.
//      *
//      * Requirements:
//      *
//      * - the caller must have ``role``'s admin role.
//      */
//     function grantRole(bytes32 role, address account) public virtual {
//         require(hasRole(_roles[role].adminRole, _msgSender()), "AccessControl: sender must be an admin to grant");

//         _grantRole(role, account);
//     }

//     /**
//      * @dev Revokes `role` from `account`.
//      *
//      * If `account` had been granted `role`, emits a {RoleRevoked} event.
//      *
//      * Requirements:
//      *
//      * - the caller must have ``role``'s admin role.
//      */
//     function revokeRole(bytes32 role, address account) public virtual {
//         require(hasRole(_roles[role].adminRole, _msgSender()), "AccessControl: sender must be an admin to revoke");

//         _revokeRole(role, account);
//     }

//     /**
//      * @dev Revokes `role` from the calling account.
//      *
//      * Roles are often managed via {grantRole} and {revokeRole}: this function's
//      * purpose is to provide a mechanism for accounts to lose their privileges
//      * if they are compromised (such as when a trusted device is misplaced).
//      *
//      * If the calling account had been granted `role`, emits a {RoleRevoked}
//      * event.
//      *
//      * Requirements:
//      *
//      * - the caller must be `account`.
//      */
//     function renounceRole(bytes32 role, address account) public virtual {
//         require(account == _msgSender(), "AccessControl: can only renounce roles for self");

//         _revokeRole(role, account);
//     }

//     /**
//      * @dev Grants `role` to `account`.
//      *
//      * If `account` had not been already granted `role`, emits a {RoleGranted}
//      * event. Note that unlike {grantRole}, this function doesn't perform any
//      * checks on the calling account.
//      *
//      * [WARNING]
//      * ====
//      * This function should only be called from the constructor when setting
//      * up the initial roles for the system.
//      *
//      * Using this function in any other way is effectively circumventing the admin
//      * system imposed by {AccessControl}.
//      * ====
//      */
//     function _setupRole(bytes32 role, address account) internal virtual {
//         _grantRole(role, account);
//     }

//     /**
//      * @dev Sets `adminRole` as ``role``'s admin role.
//      *
//      * Emits a {RoleAdminChanged} event.
//      */
//     function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
//         emit RoleAdminChanged(role, _roles[role].adminRole, adminRole);
//         _roles[role].adminRole = adminRole;
//     }

//     function _grantRole(bytes32 role, address account) private {
//         if (_roles[role].members.add(account)) {
//             emit RoleGranted(role, account, _msgSender());
//         }
//     }

//     function _revokeRole(bytes32 role, address account) private {
//         if (_roles[role].members.remove(account)) {
//             emit RoleRevoked(role, account, _msgSender());
//         }
//     }
// }

// // File: openzeppelin-solidity/contracts/token/ERC20/IERC20.sol



// pragma solidity >=0.6.0 <0.8.0;

// /**
//  * @dev Interface of the ERC20 standard as defined in the EIP.
//  */
// interface IERC20 {
//     /**
//      * @dev Returns the amount of tokens in existence.
//      */
//     function totalSupply() external view returns (uint256);

//     /**
//      * @dev Returns the amount of tokens owned by `account`.
//      */
//     function balanceOf(address account) external view returns (uint256);

//     /**
//      * @dev Moves `amount` tokens from the caller's account to `recipient`.
//      *
//      * Returns a boolean value indicating whether the operation succeeded.
//      *
//      * Emits a {Transfer} event.
//      */
//     function transfer(address recipient, uint256 amount) external returns (bool);

//     /**
//      * @dev Returns the remaining number of tokens that `spender` will be
//      * allowed to spend on behalf of `owner` through {transferFrom}. This is
//      * zero by default.
//      *
//      * This value changes when {approve} or {transferFrom} are called.
//      */
//     function allowance(address owner, address spender) external view returns (uint256);

//     /**
//      * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
//      *
//      * Returns a boolean value indicating whether the operation succeeded.
//      *
//      * IMPORTANT: Beware that changing an allowance with this method brings the risk
//      * that someone may use both the old and the new allowance by unfortunate
//      * transaction ordering. One possible solution to mitigate this race
//      * condition is to first reduce the spender's allowance to 0 and set the
//      * desired value afterwards:
//      * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
//      *
//      * Emits an {Approval} event.
//      */
//     function approve(address spender, uint256 amount) external returns (bool);

//     /**
//      * @dev Moves `amount` tokens from `sender` to `recipient` using the
//      * allowance mechanism. `amount` is then deducted from the caller's
//      * allowance.
//      *
//      * Returns a boolean value indicating whether the operation succeeded.
//      *
//      * Emits a {Transfer} event.
//      */
//     function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

//     /**
//      * @dev Emitted when `value` tokens are moved from one account (`from`) to
//      * another (`to`).
//      *
//      * Note that `value` may be zero.
//      */
//     event Transfer(address indexed from, address indexed to, uint256 value);

//     /**
//      * @dev Emitted when the allowance of a `spender` for an `owner` is set by
//      * a call to {approve}. `value` is the new allowance.
//      */
//     event Approval(address indexed owner, address indexed spender, uint256 value);
// }

// // File: openzeppelin-solidity/contracts/math/SafeMath.sol



// pragma solidity >=0.6.0 <0.8.0;

// /**
//  * @dev Wrappers over Solidity's arithmetic operations with added overflow
//  * checks.
//  *
//  * Arithmetic operations in Solidity wrap on overflow. This can easily result
//  * in bugs, because programmers usually assume that an overflow raises an
//  * error, which is the standard behavior in high level programming languages.
//  * `SafeMath` restores this intuition by reverting the transaction when an
//  * operation overflows.
//  *
//  * Using this library instead of the unchecked operations eliminates an entire
//  * class of bugs, so it's recommended to use it always.
//  */
// library SafeMath {
//     /**
//      * @dev Returns the addition of two unsigned integers, reverting on
//      * overflow.
//      *
//      * Counterpart to Solidity's `+` operator.
//      *
//      * Requirements:
//      *
//      * - Addition cannot overflow.
//      */
//     function add(uint256 a, uint256 b) internal pure returns (uint256) {
//         uint256 c = a + b;
//         require(c >= a, "SafeMath: addition overflow");

//         return c;
//     }

//     /**
//      * @dev Returns the subtraction of two unsigned integers, reverting on
//      * overflow (when the result is negative).
//      *
//      * Counterpart to Solidity's `-` operator.
//      *
//      * Requirements:
//      *
//      * - Subtraction cannot overflow.
//      */
//     function sub(uint256 a, uint256 b) internal pure returns (uint256) {
//         return sub(a, b, "SafeMath: subtraction overflow");
//     }

//     /**
//      * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
//      * overflow (when the result is negative).
//      *
//      * Counterpart to Solidity's `-` operator.
//      *
//      * Requirements:
//      *
//      * - Subtraction cannot overflow.
//      */
//     function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
//         require(b <= a, errorMessage);
//         uint256 c = a - b;

//         return c;
//     }

//     /**
//      * @dev Returns the multiplication of two unsigned integers, reverting on
//      * overflow.
//      *
//      * Counterpart to Solidity's `*` operator.
//      *
//      * Requirements:
//      *
//      * - Multiplication cannot overflow.
//      */
//     function mul(uint256 a, uint256 b) internal pure returns (uint256) {
//         // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
//         // benefit is lost if 'b' is also tested.
//         // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
//         if (a == 0) {
//             return 0;
//         }

//         uint256 c = a * b;
//         require(c / a == b, "SafeMath: multiplication overflow");

//         return c;
//     }

//     /**
//      * @dev Returns the integer division of two unsigned integers. Reverts on
//      * division by zero. The result is rounded towards zero.
//      *
//      * Counterpart to Solidity's `/` operator. Note: this function uses a
//      * `revert` opcode (which leaves remaining gas untouched) while Solidity
//      * uses an invalid opcode to revert (consuming all remaining gas).
//      *
//      * Requirements:
//      *
//      * - The divisor cannot be zero.
//      */
//     function div(uint256 a, uint256 b) internal pure returns (uint256) {
//         return div(a, b, "SafeMath: division by zero");
//     }

//     /**
//      * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
//      * division by zero. The result is rounded towards zero.
//      *
//      * Counterpart to Solidity's `/` operator. Note: this function uses a
//      * `revert` opcode (which leaves remaining gas untouched) while Solidity
//      * uses an invalid opcode to revert (consuming all remaining gas).
//      *
//      * Requirements:
//      *
//      * - The divisor cannot be zero.
//      */
//     function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
//         require(b > 0, errorMessage);
//         uint256 c = a / b;
//         // assert(a == b * c + a % b); // There is no case in which this doesn't hold

//         return c;
//     }

//     /**
//      * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
//      * Reverts when dividing by zero.
//      *
//      * Counterpart to Solidity's `%` operator. This function uses a `revert`
//      * opcode (which leaves remaining gas untouched) while Solidity uses an
//      * invalid opcode to revert (consuming all remaining gas).
//      *
//      * Requirements:
//      *
//      * - The divisor cannot be zero.
//      */
//     function mod(uint256 a, uint256 b) internal pure returns (uint256) {
//         return mod(a, b, "SafeMath: modulo by zero");
//     }

//     /**
//      * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
//      * Reverts with custom message when dividing by zero.
//      *
//      * Counterpart to Solidity's `%` operator. This function uses a `revert`
//      * opcode (which leaves remaining gas untouched) while Solidity uses an
//      * invalid opcode to revert (consuming all remaining gas).
//      *
//      * Requirements:
//      *
//      * - The divisor cannot be zero.
//      */
//     function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
//         require(b != 0, errorMessage);
//         return a % b;
//     }
// }

// // File: openzeppelin-solidity/contracts/token/ERC20/SafeERC20.sol



// pragma solidity >=0.6.0 <0.8.0;




// /**
//  * @title SafeERC20
//  * @dev Wrappers around ERC20 operations that throw on failure (when the token
//  * contract returns false). Tokens that return no value (and instead revert or
//  * throw on failure) are also supported, non-reverting calls are assumed to be
//  * successful.
//  * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
//  * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
//  */
// library SafeERC20 {
//     using SafeMath for uint256;
//     using Address for address;

//     function safeTransfer(IERC20 token, address to, uint256 value) internal {
//         _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
//     }

//     function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
//         _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
//     }

//     /**
//      * @dev Deprecated. This function has issues similar to the ones found in
//      * {IERC20-approve}, and its usage is discouraged.
//      *
//      * Whenever possible, use {safeIncreaseAllowance} and
//      * {safeDecreaseAllowance} instead.
//      */
//     function safeApprove(IERC20 token, address spender, uint256 value) internal {
//         // safeApprove should only be called when setting an initial allowance,
//         // or when resetting it to zero. To increase and decrease it, use
//         // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
//         // solhint-disable-next-line max-line-length
//         require((value == 0) || (token.allowance(address(this), spender) == 0),
//             "SafeERC20: approve from non-zero to non-zero allowance"
//         );
//         _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
//     }

//     function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
//         uint256 newAllowance = token.allowance(address(this), spender).add(value);
//         _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
//     }

//     function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
//         uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");
//         _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
//     }

//     /**
//      * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
//      * on the return value: the return value is optional (but if data is returned, it must not be false).
//      * @param token The token targeted by the call.
//      * @param data The call data (encoded using abi.encode or one of its variants).
//      */
//     function _callOptionalReturn(IERC20 token, bytes memory data) private {
//         // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
//         // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that
//         // the target address contains contract code and also asserts for success in the low-level call.

//         bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
//         if (returndata.length > 0) { // Return data is optional
//             // solhint-disable-next-line max-line-length
//             require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
//         }
//     }
// }

// // File: original_contracts/routers/IRouter.sol

// pragma solidity 0.7.5;

// interface IRouter {

//     /**
//     * @dev Certain routers/exchanges needs to be initialized.
//     * This method will be called from Augustus
//     */
//     function initialize(bytes calldata data) external;

//     /**
//     * @dev Returns unique identifier for the router
//     */
//     function getKey() external pure returns(bytes32);

//     event Swapped(
//         bytes16 uuid,
//         address initiator,
//         address indexed beneficiary,
//         address indexed srcToken,
//         address indexed destToken,
//         uint256 srcAmount,
//         uint256 receivedAmount,
//         uint256 expectedAmount
//     );

//     event Bought(
//         bytes16 uuid,
//         address initiator,
//         address indexed beneficiary,
//         address indexed srcToken,
//         address indexed destToken,
//         uint256 srcAmount,
//         uint256 receivedAmount
//     );

//     event FeeTaken(
//         uint256 fee,
//         uint256 partnerShare,
//         uint256 paraswapShare
//     );
// }

// // File: original_contracts/ITokenTransferProxy.sol

// pragma solidity 0.7.5;


// interface ITokenTransferProxy {

//     function transferFrom(
//         address token,
//         address from,
//         address to,
//         uint256 amount
//     )
//         external;
// }

// // File: original_contracts/lib/Utils.sol

// pragma solidity 0.7.5;
// pragma experimental ABIEncoderV2;





// interface IERC20Permit {
//     function permit(address owner, address spender, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
// }

// library Utils {
//     using SafeMath for uint256;
//     using SafeERC20 for IERC20;

//     address constant ETH_ADDRESS = address(
//         0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE
//     );
    
//     uint256 constant MAX_UINT = type(uint256).max;

//     /**
//    * @param fromToken Address of the source token
//    * @param fromAmount Amount of source tokens to be swapped
//    * @param toAmount Minimum destination token amount expected out of this swap
//    * @param expectedAmount Expected amount of destination tokens without slippage
//    * @param beneficiary Beneficiary address
//    * 0 then 100% will be transferred to beneficiary. Pass 10000 for 100%
//    * @param path Route to be taken for this swap to take place

//    */
//     struct SellData {
//         address fromToken;
//         uint256 fromAmount;
//         uint256 toAmount;
//         uint256 expectedAmount;
//         address payable beneficiary;
//         Utils.Path[] path;
//         address payable partner;
//         uint256 feePercent;
//         bytes permit;
//         uint256 deadline;
//         bytes16 uuid;
//     }

//     struct MegaSwapSellData {
//         address fromToken;
//         uint256 fromAmount;
//         uint256 toAmount;
//         uint256 expectedAmount;
//         address payable beneficiary;
//         Utils.MegaSwapPath[] path;
//         address payable partner;
//         uint256 feePercent;
//         bytes permit;
//         uint256 deadline;
//         bytes16 uuid;
//     }

//     struct SimpleData {
//         address fromToken;
//         address toToken;
//         uint256 fromAmount;
//         uint256 toAmount;
//         uint256 expectedAmount;
//         address[] callees;
//         bytes exchangeData;
//         uint256[] startIndexes;
//         uint256[] values;
//         address payable beneficiary;
//         address payable partner;
//         uint256 feePercent;
//         bytes permit;
//         uint256 deadline;
//         bytes16 uuid;
//     }

//     struct Adapter {
//         address payable adapter;
//         uint256 percent;
//         uint256 networkFee;
//         Route[] route;
//     }

//     struct Route {
//         uint256 index;//Adapter at which index needs to be used
//         address targetExchange;
//         uint percent;
//         bytes payload;
//         uint256 networkFee;//Network fee is associated with 0xv3 trades
//     }

//     struct MegaSwapPath {
//         uint256 fromAmountPercent;
//         Path[] path;
//     }

//     struct Path {
//         address to;
//         uint256 totalNetworkFee;//Network fee is associated with 0xv3 trades
//         Adapter[] adapters;
//     }

//     function ethAddress() internal pure returns (address) {return ETH_ADDRESS;}

//     function maxUint() internal pure returns (uint256) {return MAX_UINT;}

//     function approve(
//         address addressToApprove,
//         address token,
//         uint256 amount
//     ) internal {
//         if (token != ETH_ADDRESS) {
//             IERC20 _token = IERC20(token);

//             uint allowance = _token.allowance(address(this), addressToApprove);

//             if (allowance < amount) {
//                 _token.safeApprove(addressToApprove, 0);
//                 _token.safeIncreaseAllowance(addressToApprove, MAX_UINT);
//             }
//         }
//     }

//     function transferTokens(
//         address token,
//         address payable destination,
//         uint256 amount
//     )
//     internal
//     {
//         if (amount > 0) {
//             if (token == ETH_ADDRESS) {
//                 (bool result, ) = destination.call{value: amount, gas: 10000}("");
//                 require(result, "Failed to transfer Ether");
//             }
//             else {
//                 IERC20(token).safeTransfer(destination, amount);
//             }
//         }

//     }

//     function tokenBalance(
//         address token,
//         address account
//     )
//     internal
//     view
//     returns (uint256)
//     {
//         if (token == ETH_ADDRESS) {
//             return account.balance;
//         } else {
//             return IERC20(token).balanceOf(account);
//         }
//     }

//     function permit(
//         address token,
//         bytes memory permit
//     )
//         internal
//     {
//         if (permit.length == 32 * 7) {
//             (bool success,) = token.call(abi.encodePacked(IERC20Permit.permit.selector, permit));
//             require(success, "Permit failed");
//         }
//     }

// }

// // File: original_contracts/adapters/IAdapter.sol

// pragma solidity 0.7.5;



// interface IAdapter {

//     /**
//     * @dev Certain adapters needs to be initialized.
//     * This method will be called from Augustus
//     */
//     function initialize(bytes calldata data) external;

//     /**
//    * @dev The function which performs the swap on an exchange.
//    * @param fromToken Address of the source token
//    * @param toToken Address of the destination token
//    * @param fromAmount Amount of source tokens to be swapped
//    * @param networkFee Network fee to be used in this router
//    * @param route Route to be followed
//    */
//     function swap(
//         IERC20 fromToken,
//         IERC20 toToken,
//         uint256 fromAmount,
//         uint256 networkFee,
//         Utils.Route[] calldata route
//     )
//         external
//         payable;
// }

// // File: openzeppelin-solidity/contracts/access/Ownable.sol



// pragma solidity >=0.6.0 <0.8.0;

// /**
//  * @dev Contract module which provides a basic access control mechanism, where
//  * there is an account (an owner) that can be granted exclusive access to
//  * specific functions.
//  *
//  * By default, the owner account will be the one that deploys the contract. This
//  * can later be changed with {transferOwnership}.
//  *
//  * This module is used through inheritance. It will make available the modifier
//  * `onlyOwner`, which can be applied to your functions to restrict their use to
//  * the owner.
//  */
// abstract contract Ownable is Context {
//     address private _owner;

//     event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

//     /**
//      * @dev Initializes the contract setting the deployer as the initial owner.
//      */
//     constructor () internal {
//         address msgSender = _msgSender();
//         _owner = msgSender;
//         emit OwnershipTransferred(address(0), msgSender);
//     }

//     /**
//      * @dev Returns the address of the current owner.
//      */
//     function owner() public view returns (address) {
//         return _owner;
//     }

//     /**
//      * @dev Throws if called by any account other than the owner.
//      */
//     modifier onlyOwner() {
//         require(_owner == _msgSender(), "Ownable: caller is not the owner");
//         _;
//     }

//     /**
//      * @dev Leaves the contract without owner. It will not be possible to call
//      * `onlyOwner` functions anymore. Can only be called by the current owner.
//      *
//      * NOTE: Renouncing ownership will leave the contract without an owner,
//      * thereby removing any functionality that is only available to the owner.
//      */
//     function renounceOwnership() public virtual onlyOwner {
//         emit OwnershipTransferred(_owner, address(0));
//         _owner = address(0);
//     }

//     /**
//      * @dev Transfers ownership of the contract to a new account (`newOwner`).
//      * Can only be called by the current owner.
//      */
//     function transferOwnership(address newOwner) public virtual onlyOwner {
//         require(newOwner != address(0), "Ownable: new owner is the zero address");
//         emit OwnershipTransferred(_owner, newOwner);
//         _owner = newOwner;
//     }
// }

// // File: original_contracts/TokenTransferProxy.sol

// pragma solidity 0.7.5;







// /**
// * @dev Allows owner of the contract to transfer tokens on behalf of user.
// * User will need to approve this contract to spend tokens on his/her behalf
// * on Paraswap platform
// */
// contract TokenTransferProxy is Ownable, ITokenTransferProxy {
//     using SafeERC20 for IERC20;
//     using Address for address;

//     /**
//     * @dev Allows owner of the contract to transfer tokens on user's behalf
//     * @dev Swapper contract will be the owner of this contract
//     * @param token Address of the token
//     * @param from Address from which tokens will be transferred
//     * @param to Receipent address of the tokens
//     * @param amount Amount of tokens to transfer
//     */
//     function transferFrom(
//         address token,
//         address from,
//         address to,
//         uint256 amount
//     )
//         external
//         override
//         onlyOwner
//     {   
//         require(
//             from == tx.origin ||
//             from.isContract(),
//             "Invalid from address"
//         );
        
//         IERC20(token).safeTransferFrom(from, to, amount);
//     }
// }

// // File: original_contracts/AugustusStorage.sol

// pragma solidity 0.7.5;


// contract AugustusStorage {

//     struct FeeStructure {
//         uint256 partnerShare;
//         bool noPositiveSlippage;
//         bool positiveSlippageToUser;
//         uint16 feePercent;
//         string partnerId;
//         bytes data;
//     }

//     ITokenTransferProxy internal tokenTransferProxy;
//     address payable internal feeWallet;
    
//     mapping(address => FeeStructure) internal registeredPartners;

//     mapping (bytes4 => address) internal selectorVsRouter;
//     mapping (bytes32 => bool) internal adapterInitialized;
//     mapping (bytes32 => bytes) internal adapterVsData;

//     mapping (bytes32 => bytes) internal routerData;
//     mapping (bytes32 => bool) internal routerInitialized;


//     bytes32 public constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");

//     bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");

// }

// // File: original_contracts/AugustusSwapper.sol

// pragma solidity 0.7.5;










// contract AugustusSwapper is AugustusStorage, AccessControl {
//     using SafeMath for uint256;
//     using SafeERC20 for IERC20;

//     event AdapterInitialized(address indexed adapter);

//     event RouterInitialized(address indexed router);

//     /**
//      * @dev Throws if called by any account other than the admin.
//      */
//     modifier onlyAdmin() {
//         require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "caller is not the admin");
//         _;
//     }

//     constructor(address payable _feeWallet) public {
//         TokenTransferProxy lTokenTransferProxy = new TokenTransferProxy();
//         tokenTransferProxy = ITokenTransferProxy(lTokenTransferProxy);
//         feeWallet = _feeWallet;
//         _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
//     }
    
//     receive () payable external {

//     }

//     fallback() external payable {
//         bytes4 selector = msg.sig;
//         //Figure out the router contract for the given function
//         address implementation = getImplementation(selector);
//         if (implementation == address(0)) {
//             _revertWithData(
//                 abi.encodeWithSelector(
//                     bytes4(keccak256("NotImplementedError(bytes4)")),
//                     selector
//                 )
//             );
//         }

//         //Delegate call to the router
//         (bool success, bytes memory resultData) = implementation.delegatecall(msg.data);
//         if (!success) {
//             _revertWithData(resultData);
//         }

//         _returnWithData(resultData);
//     }

//     function initializeAdapter(address adapter, bytes calldata data) external onlyAdmin {

//         require(
//             hasRole(WHITELISTED_ROLE, adapter),
//             "Exchange not whitelisted"
//         );
//         (bool success,) = adapter.delegatecall(abi.encodeWithSelector(IAdapter.initialize.selector, data));
//         require(success, "Failed to initialize adapter");
//         emit AdapterInitialized(adapter);
//     }

//     function initializeRouter(address router, bytes calldata data) external onlyAdmin {

//         require(
//             hasRole(ROUTER_ROLE, router),
//             "Router not whitelisted"
//         );
//         (bool success,) = router.delegatecall(abi.encodeWithSelector(IRouter.initialize.selector, data));
//         require(success, "Failed to initialize router");
//         emit RouterInitialized(router);
//     } 

    
//     function getImplementation(bytes4 selector) public view returns(address) {
//         return selectorVsRouter[selector];
//     }

//     function getVersion() external pure returns(string memory) {
//         return "5.0.0";
//     }

//     function getPartnerFeeStructure(address partner) public view returns (FeeStructure memory) {
//         return registeredPartners[partner];
//     }

//     function getFeeWallet() external view returns(address) {
//         return feeWallet;
//     }

//     function setFeeWallet(address payable _feeWallet) external onlyAdmin {
//         require(_feeWallet != address(0), "Invalid address");
//         feeWallet = _feeWallet;
//     }

//     function registerPartner(
//         address partner,
//         uint256 _partnerShare,
//         bool _noPositiveSlippage,
//         bool _positiveSlippageToUser,
//         uint16 _feePercent,
//         string calldata partnerId,
//         bytes calldata _data
//     )
//         external
//         onlyAdmin
//     {   
//         require(partner != address(0), "Invalid partner");
//         FeeStructure storage feeStructure = registeredPartners[partner];
//         require(feeStructure.partnerShare == 0, "Already registered");
//         require(_partnerShare > 0 && _partnerShare < 10000, "Invalid values");
//         require(_feePercent <= 10000, "Invalid values");

//         feeStructure.partnerShare = _partnerShare;
//         feeStructure.noPositiveSlippage = _noPositiveSlippage;
//         feeStructure.positiveSlippageToUser = _positiveSlippageToUser;
//         feeStructure.partnerId = partnerId;
//         feeStructure.feePercent = _feePercent;
//         feeStructure.data = _data;
//     }

//     function setImplementation(bytes4 selector, address implementation) external onlyAdmin {
//         require(
//             hasRole(ROUTER_ROLE, implementation),
//             "Router is not whitelisted"
//         );
//         selectorVsRouter[selector] = implementation;
//     }

//     /**
//     * @dev Allows admin of the contract to transfer any tokens which are assigned to the contract
//     * This method is for safety if by any chance tokens or ETHs are assigned to the contract by mistake
//     * @dev token Address of the token to be transferred
//     * @dev destination Recepient of the token
//     * @dev amount Amount of tokens to be transferred
//     */
//     function transferTokens(
//         address token,
//         address payable destination,
//         uint256 amount
//     )
//         external
//         onlyAdmin
//     {
//         if (amount > 0) {
//             if (token == address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)) {
//                 (bool result, ) = destination.call{value: amount, gas: 10000}("");
//                 require(result, "Failed to transfer Ether");
//             }
//             else {
//                 IERC20(token).safeTransfer(destination, amount);
//             }
//         }
//     }

//       function isAdapterInitialized(bytes32 key) public view returns(bool) {
//         return adapterInitialized[key];
//     }

//     function getAdapterData(bytes32 key) public view returns(bytes memory) {
//         return adapterVsData[key];
//     }

//     function isRouterInitialized(bytes32 key) public view returns (bool) {
//         return routerInitialized[key];
//     }

//     function getRouterData(bytes32 key) public view returns (bytes memory) {
//         return routerData[key];
//     }

//     function getTokenTransferProxy() public view returns (address) {
//         return address(tokenTransferProxy);
//     }

//     function _revertWithData(bytes memory data) private pure {
//         assembly { revert(add(data, 32), mload(data)) }
//     }

//     function _returnWithData(bytes memory data) private pure {
//         assembly { return(add(data, 32), mload(data)) }
//     }

// }