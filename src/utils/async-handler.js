const asyncHandler = (requestHandler) => {
  return (req, res, next) => {
    Promise.resolve(requestHandler(req, res, next)).catch(next);
  };
};

export { asyncHandler };

// TRY-CATCH version of async-handler

// const asyncHandler = (requestHandler) => {
//   return async (req, res, next) => {
//     try {
//       await requestHandler(req, res, next);
//     } catch (error) {
//       next(error);
//     }
//   };
// };

// export { asyncHandler };
